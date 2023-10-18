/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"time"

	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	v1 "k8s.io/api/core/v1"
	apiErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	awsv1alpha1 "github.com/zak905/kube-ecr-secrets-operator/api/v1alpha1"
)

const (
	SecretsProcessingReason = "SecretsProcessing"
	SecretsUpdatedReason    = "SecretsUpdated"

	ReadyCondition = "Ready"

	SecretsUpdatedMessageTemplate = "AWS ECR secret with type kubernetes.io/dockerconfigjson have been created/updated successfully in namespaces: %s" +
		" next update at: %s"
	SecretsProcessingMessageTemplate = "creating/updating secrets in namespaces: %s"
)

// AWSECRCredentialReconciler reconciles a AWSECRCredential object
type AWSECRCredentialReconciler struct {
	client.Client
	Recorder record.EventRecorder
}

const expiryAnnotation = "expiry"

type DockerServerAuthInfo struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Auth     string `json:"auth"`
}

type DockerAuthConfig struct {
	Auths map[string]DockerServerAuthInfo `json:"auths"`
}

// StatusChangePredicate implements a default update predicate function on status change.
// This predicate will skip update events that have a change in the object's status.
type StatusChangePredicate struct {
	predicate.Funcs
}

func (StatusChangePredicate) Update(e event.UpdateEvent) bool {
	old := e.ObjectOld.(*awsv1alpha1.AWSECRCredential)
	new := e.ObjectNew.(*awsv1alpha1.AWSECRCredential)

	return reflect.DeepEqual(old.Status, new.Status)
}

//+kubebuilder:rbac:groups=aws.zakariaamine.com,resources=awsecrcredentials,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=aws.zakariaamine.com,resources=awsecrcredentials/finalizers,verbs=update
//+kubebuilder:rbac:groups=aws.zakariaamine.com,resources=awsecrcredentials/status,verbs=get;update;patch
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=namespaces,verbs=list;watch
//+kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the AWSECRCredential object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.11.0/pkg/reconcile
func (r *AWSECRCredentialReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	result := ctrl.Result{}

	awsECRCredentials := &awsv1alpha1.AWSECRCredential{}
	if err := r.Client.Get(ctx, client.ObjectKey{Name: req.Name}, awsECRCredentials); err != nil {
		if apiErrors.IsNotFound(err) {
			//means object was deleted, so we do nothing
			return result, nil
		}
		return result, err
	}

	dockerConfig, expiresAt, err := getDockerJSONConfigFromAWS(ctx, awsECRCredentials.Spec.AWSAccess)
	if err != nil {
		r.Recorder.Event(awsECRCredentials, v1.EventTypeWarning, "GetAWSAuthTokenFailed", err.Error())
		return result, fmt.Errorf("unable to create docker secret: %w", err)
	}

	if err := r.setStatus(ctx, awsECRCredentials, metav1.Condition{
		Status:  metav1.ConditionFalse,
		Type:    ReadyCondition,
		Reason:  SecretsProcessingReason,
		Message: fmt.Sprintf(SecretsProcessingMessageTemplate, awsECRCredentials.Spec.Namespaces),
	}); err != nil {
		r.Recorder.Event(awsECRCredentials, v1.EventTypeWarning, "StatusUpdateFailed", err.Error())
		return result, err
	}

	for _, namespace := range awsECRCredentials.Spec.Namespaces {
		log.Info("", "namespace", namespace, "message", "processing")
		existingDockerSecret := &v1.Secret{}
		if err := r.Client.Get(ctx,
			client.ObjectKey{
				Name:      awsECRCredentials.Spec.SecretName,
				Namespace: namespace,
			}, existingDockerSecret); err != nil {

			if !apiErrors.IsNotFound(err) {
				wrappedErr := fmt.Errorf("got %s status from API server: %w", apiErrors.ReasonForError(err), err)
				if err := r.setStatus(ctx, awsECRCredentials, metav1.Condition{
					Status:  metav1.ConditionFalse,
					Type:    ReadyCondition,
					Reason:  SecretsProcessingReason,
					Message: wrappedErr.Error(),
				}); err != nil {
					r.Recorder.Event(awsECRCredentials, v1.EventTypeWarning, "StatusUpdateFailed", err.Error())
					return result, err
				}

				r.Recorder.Event(awsECRCredentials, v1.EventTypeWarning, "GetSecretError", err.Error())
				return result, wrappedErr
			}

			log.Info("", "namespace", namespace, "message", "creating secret")

			dockerSecret := newDockerSecret(awsECRCredentials, dockerConfig, expiresAt)
			dockerSecret.Namespace = namespace
			if err := r.Client.Create(ctx, dockerSecret); err != nil {
				wrappedErr := fmt.Errorf("error creating docker secret in namespace %s, %w", namespace, err)
				if err := r.setStatus(ctx, awsECRCredentials, metav1.Condition{
					Status:  metav1.ConditionFalse,
					Type:    ReadyCondition,
					Reason:  SecretsProcessingReason,
					Message: wrappedErr.Error(),
				}); err != nil {
					r.Recorder.Event(awsECRCredentials, v1.EventTypeWarning, "StatusUpdateFailed", err.Error())
					return result, err
				}

				r.Recorder.Event(awsECRCredentials, v1.EventTypeWarning, "CreateSecretError", err.Error())
				return result, wrappedErr
			}

			r.Recorder.Eventf(awsECRCredentials, v1.EventTypeNormal, "SecretCreationSuccess", "secret %s created successfully in namespace %s",
				awsECRCredentials.Spec.SecretName, namespace)
		} else {
			existingDockerSecret.Data[".dockerconfigjson"] = dockerConfig
			existingDockerSecret.Annotations[expiryAnnotation] = expiresAt.Format(time.RFC3339)
			if err := r.Client.Update(ctx, existingDockerSecret); err != nil {
				wrappedErr := fmt.Errorf("error update docker secret in namespace %s, %w", namespace, err)
				if err := r.setStatus(ctx, awsECRCredentials, metav1.Condition{
					Status:  metav1.ConditionFalse,
					Type:    ReadyCondition,
					Reason:  SecretsProcessingReason,
					Message: wrappedErr.Error(),
				}); err != nil {
					r.Recorder.Event(awsECRCredentials, v1.EventTypeWarning, "StatusUpdateFailed", err.Error())
					return result, err
				}

				r.Recorder.Event(awsECRCredentials, v1.EventTypeWarning, "UpdateSecretError", err.Error())
				return result, wrappedErr
			}

			r.Recorder.Eventf(awsECRCredentials, v1.EventTypeNormal, "SecretUpdateSuccess", "secret %s updated successfully in namespace %s",
				awsECRCredentials.Spec.SecretName, namespace)
		}
	}

	if err := r.setStatus(ctx, awsECRCredentials, metav1.Condition{
		Status:  metav1.ConditionTrue,
		Type:    ReadyCondition,
		Reason:  SecretsUpdatedReason,
		Message: fmt.Sprintf(SecretsUpdatedMessageTemplate, awsECRCredentials.Spec.Namespaces, expiresAt.String()),
	}); err != nil {
		r.Recorder.Event(awsECRCredentials, v1.EventTypeWarning, "StatusUpdateFailed", err.Error())
		return result, err
	}

	result.RequeueAfter = time.Until(*expiresAt)

	return result, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AWSECRCredentialReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&awsv1alpha1.AWSECRCredential{}).
		WithEventFilter(StatusChangePredicate{}).
		Complete(r)
}

func (r *AWSECRCredentialReconciler) setStatus(ctx context.Context, credential *awsv1alpha1.AWSECRCredential, condition metav1.Condition) error {
	oldObj := credential.DeepCopy()

	meta.SetStatusCondition(&credential.Status.Conditions, condition)

	if err := r.Client.Status().Patch(ctx, credential, client.MergeFrom(oldObj)); err != nil {
		return fmt.Errorf("failed updating AWSECRCredential status: %w", err)
	}

	return nil
}

func getDockerJSONConfigFromAWS(ctx context.Context, access awsv1alpha1.AWSAccess) ([]byte, *time.Time, error) {
	awsAccessKeyID, err := base64.StdEncoding.DecodeString(access.AccessKeyID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to base64 decode the accessKeyID: %w", err)
	}
	awsSecretAccessKey, err := base64.StdEncoding.DecodeString(access.SecretAccessKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to base64 decode the secretAccessKey: %w", err)
	}

	authData, err := getAWSECRAuthToken(ctx, string(awsAccessKeyID), string(awsSecretAccessKey), access.Region)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get ECR authorization token: %w", err)
	}

	url, err := url.Parse(*authData.ProxyEndpoint)
	if err != nil {
		return nil, nil, err
	}

	decodedToken, err := base64.StdEncoding.DecodeString(*authData.AuthorizationToken)
	if err != nil {
		return nil, nil, err
	}
	password := strings.Split(string(decodedToken), ":")[1]
	dockerConfig := DockerAuthConfig{
		Auths: map[string]DockerServerAuthInfo{
			url.Hostname(): {Username: "AWS", Password: password, Auth: *authData.AuthorizationToken},
		},
	}

	asJSON, err := json.Marshal(dockerConfig)

	return asJSON, authData.ExpiresAt, err
}

func getAWSECRAuthToken(ctx context.Context, accessKeyID, secretAccessKey, region string) (*types.AuthorizationData, error) {
	cfg, err := awsConfig.LoadDefaultConfig(ctx,
		awsConfig.WithRegion(region),
		awsConfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, "")),
	)
	if err != nil {
		return nil, err
	}

	ecrSvc := ecr.NewFromConfig(cfg)

	output, err := ecrSvc.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return nil, fmt.Errorf("unable to get ECR authorization token: %w", err)
	}

	return &output.AuthorizationData[0], nil
}

// Creates the Kubernetes secret
// the created secret has the namespace not set
func newDockerSecret(ecrCredential *awsv1alpha1.AWSECRCredential,
	dockerConfig []byte, expiresAt *time.Time) *v1.Secret {
	return &v1.Secret{
		Type: v1.SecretTypeDockerConfigJson,
		ObjectMeta: metav1.ObjectMeta{
			Name: ecrCredential.Spec.SecretName,
			Annotations: map[string]string{
				expiryAnnotation: expiresAt.Format(time.RFC3339),
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: ecrCredential.APIVersion,
					Kind:       ecrCredential.Kind,
					UID:        ecrCredential.GetUID(),
					Name:       ecrCredential.Name,
				},
			},
		},
		Data: map[string][]byte{".dockerconfigjson": dockerConfig},
	}
}

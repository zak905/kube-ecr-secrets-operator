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
	"net/http"
	"net/url"
	"strings"
	"time"

	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	v1 "k8s.io/api/core/v1"
	apiErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	awsv1alpha1 "github.com/zak905/kube-ecr-secrets-operator/api/v1alpha1"
)

// AWSECRCredentialReconciler reconciles a AWSECRCredential object
type AWSECRCredentialReconciler struct {
	client.Client
	Scheme *runtime.Scheme
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

//+kubebuilder:rbac:groups=aws.zakariaamine.com,resources=awsecrcredentials,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=aws.zakariaamine.com,resources=awsecrcredentials/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=namespaces,verbs=list;watch

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

	var awsECRCredentials awsv1alpha1.AWSECRCredential
	if err := r.Client.Get(ctx, client.ObjectKey{Name: req.Name}, &awsECRCredentials); err != nil {
		statusErr, ok := err.(*apiErrors.StatusError)
		if !ok {
			return ctrl.Result{}, fmt.Errorf("could not process API error")
		}

		if statusErr.ErrStatus.Code == http.StatusNotFound {
			//means object was deleted, so we do nothing
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	var awsCredentialsSecret v1.Secret
	if err := r.Client.Get(ctx,
		client.ObjectKey{
			Name:      awsECRCredentials.Spec.AWSAccess.SecretName,
			Namespace: awsECRCredentials.Spec.AWSAccess.Namespace,
		}, &awsCredentialsSecret); err != nil {
		return ctrl.Result{}, fmt.Errorf("secret %s not found in namespace %s",
			awsECRCredentials.Spec.AWSAccess.SecretName,
			awsECRCredentials.Spec.AWSAccess.Namespace)
	}

	dockerConfig, expiresAt, err := createDockerJSONConfig(ctx, awsCredentialsSecret.Data)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to create docker auth info: %w", err)
	}

	for _, namespace := range awsECRCredentials.Spec.Namespaces {
		log.Info("processing", "namespace", namespace)
		var dockerSecret v1.Secret
		if err := r.Client.Get(ctx,
			client.ObjectKey{
				Name:      awsECRCredentials.Spec.SecretName,
				Namespace: namespace,
			}, &dockerSecret); err != nil {
			statusErr, ok := err.(*apiErrors.StatusError)
			if !ok {
				return ctrl.Result{}, fmt.Errorf("could not process API error")
			}

			log.Info("looking for existing secret", "status", statusErr.ErrStatus.Code)

			if statusErr.ErrStatus.Code == http.StatusNotFound {
				dockerSecret = v1.Secret{
					Type: v1.SecretTypeDockerConfigJson,
					ObjectMeta: metav1.ObjectMeta{
						Name:      awsECRCredentials.Spec.SecretName,
						Namespace: namespace,
						Annotations: map[string]string{
							expiryAnnotation: expiresAt.Format(time.RFC3339),
						},
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion: awsECRCredentials.APIVersion,
								Kind:       awsECRCredentials.Kind,
								UID:        awsECRCredentials.GetUID(),
								Name:       awsECRCredentials.Name,
							},
						},
					},
					Data: map[string][]byte{".dockerconfigjson": dockerConfig},
				}

				log.Info("creating secret", "namespace", namespace)

				if err := r.Client.Create(ctx, &dockerSecret); err != nil {
					return ctrl.Result{}, fmt.Errorf("error creating docker secret in namespace %s, %w", namespace, err)
				}

				log.Info("creating secret", "namespace", namespace)

				continue
			}

			return ctrl.Result{}, fmt.Errorf("got %d status from API server, message: %s",
				statusErr.ErrStatus.Code, statusErr.Status().Message)
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AWSECRCredentialReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&awsv1alpha1.AWSECRCredential{}).
		Complete(r)
}

func createDockerJSONConfig(ctx context.Context, secretData map[string][]byte) ([]byte, *time.Time, error) {
	authData, err := getAWSAuthToken(ctx, secretData)
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

func getAWSAuthToken(ctx context.Context, secretData map[string][]byte) (*types.AuthorizationData, error) {
	accessKeyID := string(secretData["AWS_ACCESS_KEY_ID"])
	secretAccessKey := string(secretData["AWS_SECRET_ACCESS_KEY"])
	region := string(secretData["AWS_REGION"])

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

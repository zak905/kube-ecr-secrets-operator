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

	awsv1alpha2 "github.com/zak905/kube-ecr-secrets-operator/api/v1alpha2"
	"github.com/zak905/kube-ecr-secrets-operator/common"

	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	v1 "k8s.io/api/core/v1"
	apiErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const (
	SecretsProcessingReason = "SecretsProcessing"
	SecretsUpdatedReason    = "SecretsUpdated"

	ReadyCondition = "Ready"

	SecretsUpdatedMessageTemplate = "AWS ECR secret with type kubernetes.io/dockerconfigjson have been created/updated successfully in namespaces: %s" +
		" next update at: %s"
	SecretsProcessingMessageTemplate = "creating/updating secrets in namespaces: %s"
)

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
	switch e.ObjectOld.(type) {
	case (*awsv1alpha2.AWSECRImagePullSecret):
		old := e.ObjectOld.(*awsv1alpha2.AWSECRImagePullSecret)
		new := e.ObjectNew.(*awsv1alpha2.AWSECRImagePullSecret)
		return reflect.DeepEqual(old.Status, new.Status)
	case (*awsv1alpha2.ClusterAWSECRImagePullSecret):
		old := e.ObjectOld.(*awsv1alpha2.ClusterAWSECRImagePullSecret)
		new := e.ObjectNew.(*awsv1alpha2.ClusterAWSECRImagePullSecret)
		return reflect.DeepEqual(old.Status, new.Status)
	}

	return true
}

type GenericAWSECRPullSecretReconciler[reconciled awsv1alpha2.AWSECRImagePullSecret | awsv1alpha2.ClusterAWSECRImagePullSecret] struct {
	client.Client
	Recorder record.EventRecorder
}

// SetupWithManager sets up the controller with the Manager.
func (r *GenericAWSECRPullSecretReconciler[a]) SetupWithManager(mgr ctrl.Manager) error {
	controller := ctrl.NewControllerManagedBy(mgr)
	switch reflect.TypeFor[a]() {
	case reflect.TypeOf(awsv1alpha2.AWSECRImagePullSecret{}):
		controller.For(&awsv1alpha2.AWSECRImagePullSecret{})
	case reflect.TypeOf(awsv1alpha2.ClusterAWSECRImagePullSecret{}):
		controller.For(&awsv1alpha2.ClusterAWSECRImagePullSecret{})
	}

	return controller.WithEventFilter(StatusChangePredicate{}).
		Complete(r)
}

//+kubebuilder:rbac:groups=aws.zakariaamine.com,resources=clusterawsecrimagepullsecrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=aws.zakariaamine.com,resources=clusterawsecrimagepullsecrets/finalizers,verbs=update
//+kubebuilder:rbac:groups=aws.zakariaamine.com,resources=clusterawsecrimagepullsecrets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=namespaces,verbs=list;watch
//+kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

//+kubebuilder:rbac:groups=aws.zakariaamine.com,resources=awsecrimagepullsecrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=aws.zakariaamine.com,resources=awsecrimagepullsecrets/finalizers,verbs=update
//+kubebuilder:rbac:groups=aws.zakariaamine.com,resources=awsecrimagepullsecrets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.11.0/pkg/reconcile
func (r *GenericAWSECRPullSecretReconciler[a]) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	result := ctrl.Result{}

	ecrcredentials := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "aws.zakariaamine.com/v1alpha2",
			"kind":       reflect.TypeFor[a]().Name(),
		},
	}

	if err := r.Client.Get(ctx, client.ObjectKey{Name: req.Name, Namespace: req.Namespace},
		ecrcredentials); err != nil {
		if apiErrors.IsNotFound(err) {
			//means object was deleted, so we do nothing
			return result, nil
		}
		return result, err
	}

	accessKeyID, _, err := unstructured.NestedString(ecrcredentials.Object, "spec", "awsAccess", "accessKeyId")
	if err != nil {
		return result, fmt.Errorf("unable to read spec.awsAccess.accessKeyId field in CR: %w", err)
	}
	secretAccessKey, _, err := unstructured.NestedString(ecrcredentials.Object, "spec", "awsAccess", "secretAccessKey")
	if err != nil {
		return result, fmt.Errorf("unable to read spec.awsAccess.secretAccessKey field in CR: %w", err)
	}
	region, _, err := unstructured.NestedString(ecrcredentials.Object, "spec", "awsAccess", "region")
	if err != nil {
		return result, fmt.Errorf("unable to read spec.awsAccess.region field in CR: %w", err)
	}

	dockerConfig, expiresAt, err := getDockerJSONConfigFromAWS(ctx, common.AWSAccess{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		Region:          region,
	})
	if err != nil {
		r.Recorder.Event(ecrcredentials, v1.EventTypeWarning, "GetAWSAuthTokenFailed", err.Error())
		return result, fmt.Errorf("unable to create docker secret: %w", err)
	}

	if err := r.setStatus(ctx, ecrcredentials, metav1.Condition{
		Status:  metav1.ConditionFalse,
		Type:    ReadyCondition,
		Reason:  SecretsProcessingReason,
		Message: fmt.Sprintf(SecretsProcessingMessageTemplate, ecrcredentials.GetNamespace()),
	}); err != nil {
		r.Recorder.Event(ecrcredentials, v1.EventTypeWarning, "StatusUpdateFailed", err.Error())
		return result, err
	}

	secretName, _, err := unstructured.NestedString(ecrcredentials.Object, "spec", "secretName")
	if err != nil {
		return result, fmt.Errorf("unable to read spec.secretName field in CR: %w", err)
	}

	var managedNs string

	rType := reflect.TypeFor[a]()

	switch rType {
	case reflect.TypeOf(awsv1alpha2.AWSECRImagePullSecret{}):
		managedNs = ecrcredentials.GetNamespace()
		if err := r.createOrUpdateImagePullSecret(ctx, secretName, managedNs,
			ecrcredentials, dockerConfig, expiresAt); err != nil {
			return result, fmt.Errorf("unable to create or update secret: %w", err)
		}
	case reflect.TypeOf(awsv1alpha2.ClusterAWSECRImagePullSecret{}):
		namespaces, _, err := unstructured.NestedStringSlice(ecrcredentials.Object, "spec", "namespaces")
		if err != nil {
			return result, fmt.Errorf("unable to read spec.namespaces field in CR: %w", err)
		}
		managedNs = fmt.Sprintf("%s", namespaces)
		for _, namespace := range namespaces {
			if err := r.createOrUpdateImagePullSecret(ctx, secretName, namespace,
				ecrcredentials, dockerConfig, expiresAt); err != nil {
				return result, fmt.Errorf("failed to create or update secret: %w", err)
			}
		}
	}

	if err := r.setStatus(ctx, ecrcredentials, metav1.Condition{
		Status:  metav1.ConditionTrue,
		Type:    ReadyCondition,
		Reason:  SecretsUpdatedReason,
		Message: fmt.Sprintf(SecretsUpdatedMessageTemplate, managedNs, expiresAt.String()),
	}); err != nil {
		r.Recorder.Event(ecrcredentials, v1.EventTypeWarning, "StatusUpdateFailed", err.Error())
		return result, err
	}

	result.RequeueAfter = time.Until(*expiresAt)

	return result, nil
}

func (r *GenericAWSECRPullSecretReconciler[a]) setStatus(ctx context.Context,
	credential *unstructured.Unstructured, condition metav1.Condition) error {
	oldObj := credential.DeepCopy()
	log := log.FromContext(ctx)

	conditionsRaw, _, err := unstructured.NestedSlice(oldObj.Object, "status", "conditions")
	if err != nil {
		return fmt.Errorf("unable to read status.conditions field in CR: %w", err)
	}

	conditions, err := convertToConditions(conditionsRaw)
	if err != nil {
		return fmt.Errorf("conversion failed: %w", err)
	}

	meta.SetStatusCondition(&conditions, condition)
	status, ok := credential.Object["status"].(map[string]interface{})
	if !ok || status == nil {
		status = map[string]interface{}{}
	}
	status["conditions"] = conditions
	credential.Object["status"] = status

	if err := r.Client.Status().Patch(ctx, credential, client.MergeFrom(oldObj)); err != nil {
		return fmt.Errorf("failed updating AWSECRCredential status: %w", err)
	}

	log.Info("status update successfully")

	return nil
}

func (r *GenericAWSECRPullSecretReconciler[a]) createOrUpdateImagePullSecret(ctx context.Context, secretName, namespace string,
	ecrcredentials *unstructured.Unstructured, dockerConfig []byte, expiresAt *time.Time) error {
	log := log.FromContext(ctx)
	existingDockerSecret := &v1.Secret{}
	if err := r.Client.Get(ctx,
		client.ObjectKey{
			Name:      secretName,
			Namespace: namespace,
		}, existingDockerSecret); err != nil {

		if !apiErrors.IsNotFound(err) {
			wrappedErr := fmt.Errorf("got %s status from API server: %w", apiErrors.ReasonForError(err), err)
			if err := r.setStatus(ctx, ecrcredentials, metav1.Condition{
				Status:  metav1.ConditionFalse,
				Type:    ReadyCondition,
				Reason:  SecretsProcessingReason,
				Message: wrappedErr.Error(),
			}); err != nil {
				r.Recorder.Event(ecrcredentials, v1.EventTypeWarning, "StatusUpdateFailed", err.Error())
				return err
			}

			r.Recorder.Event(ecrcredentials, v1.EventTypeWarning, "GetSecretError", err.Error())
			return wrappedErr
		}

		log.Info("creating secret", "namespace", namespace)

		dockerSecret := newDockerSecret(ecrcredentials, secretName, dockerConfig, expiresAt)
		dockerSecret.Namespace = namespace
		if err := r.Client.Create(ctx, dockerSecret); err != nil {
			wrappedErr := fmt.Errorf("error creating docker secret in namespace %s, %w", namespace, err)
			if err := r.setStatus(ctx, ecrcredentials, metav1.Condition{
				Status:  metav1.ConditionFalse,
				Type:    ReadyCondition,
				Reason:  SecretsProcessingReason,
				Message: wrappedErr.Error(),
			}); err != nil {
				r.Recorder.Event(ecrcredentials, v1.EventTypeWarning, "StatusUpdateFailed", err.Error())
				return err
			}

			r.Recorder.Event(ecrcredentials, v1.EventTypeWarning, "CreateSecretError", err.Error())
			return wrappedErr
		}

		r.Recorder.Eventf(ecrcredentials, v1.EventTypeNormal, "SecretCreationSuccess", "secret %s created successfully in namespace %s",
			secretName, namespace)
	} else {
		existingDockerSecret.Data[".dockerconfigjson"] = dockerConfig
		if existingDockerSecret.Annotations == nil {
			existingDockerSecret.Annotations = map[string]string{}
		}
		existingDockerSecret.Annotations[expiryAnnotation] = expiresAt.Format(time.RFC3339)
		if err := r.Client.Update(ctx, existingDockerSecret); err != nil {
			wrappedErr := fmt.Errorf("error update docker secret in namespace %s, %w", namespace, err)
			if err := r.setStatus(ctx, ecrcredentials, metav1.Condition{
				Status:  metav1.ConditionFalse,
				Type:    ReadyCondition,
				Reason:  SecretsProcessingReason,
				Message: wrappedErr.Error(),
			}); err != nil {
				r.Recorder.Event(ecrcredentials, v1.EventTypeWarning, "StatusUpdateFailed", err.Error())
				return err
			}

			r.Recorder.Event(ecrcredentials, v1.EventTypeWarning, "UpdateSecretError", err.Error())
			return wrappedErr
		}

		r.Recorder.Eventf(ecrcredentials, v1.EventTypeNormal, "SecretUpdateSuccess", "secret %s updated successfully in namespace %s",
			secretName, namespace)
	}

	return nil
}

func getDockerJSONConfigFromAWS(ctx context.Context, access common.AWSAccess) ([]byte, *time.Time, error) {
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
func newDockerSecret(awsCR *unstructured.Unstructured, secretName string,
	dockerConfig []byte, expiresAt *time.Time) *v1.Secret {
	return &v1.Secret{
		Type: v1.SecretTypeDockerConfigJson,
		ObjectMeta: metav1.ObjectMeta{
			Name: secretName,
			Annotations: map[string]string{
				expiryAnnotation: expiresAt.Format(time.RFC3339),
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: awsCR.GetAPIVersion(),
					Kind:       awsCR.GetKind(),
					UID:        awsCR.GetUID(),
					Name:       awsCR.GetName(),
				},
			},
		},
		Data: map[string][]byte{".dockerconfigjson": dockerConfig},
	}
}

func convertToConditions(in []interface{}) ([]metav1.Condition, error) {
	inb, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("failed to convert raw interface to json: %w", err)
	}

	var conditions []metav1.Condition

	if err := json.Unmarshal(inb, &conditions); err != nil {
		return nil, fmt.Errorf("failed to unmarshall bytes into conditions slice: %w", err)
	}

	return conditions, nil
}

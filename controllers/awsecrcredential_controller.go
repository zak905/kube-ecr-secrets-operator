package controllers

import (
	"context"

	apiErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	awsv1alpha1 "github.com/zak905/kube-ecr-secrets-operator/api/v1alpha1"

	awsv1alpha2 "github.com/zak905/kube-ecr-secrets-operator/api/v1alpha2"
)

// AWSECRCredentialReconciler reconciles a AWSECRCredential object
type AWSECRCredentialReconciler struct {
	client.Client
	Recorder record.EventRecorder
}

//+kubebuilder:rbac:groups=aws.zakariaamine.com,resources=awsecrcredentials,verbs=get;list;watch;create;delete

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

	log.Info("object of type AWSECRCredential is deprecated, converting to ClusterAWSECRImagePullSecret")

	converted := toAlpha1V2ClusterAWSECRImagePullSecret(awsECRCredentials)

	if err := r.Client.Delete(ctx, awsECRCredentials); err != nil {
		return result, err
	}

	log.Info("object of type AWSECRCredential deleted successfully, attempting to create a new ClusterAWSECRImagePullSecret")

	if err := r.Client.Create(ctx, converted); err != nil {
		return result, err
	}

	log.Info("ClusterAWSECRImagePullSecret created successfully")

	return result, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AWSECRCredentialReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&awsv1alpha1.AWSECRCredential{}).
		Complete(r)
}

func toAlpha1V2ClusterAWSECRImagePullSecret(in *awsv1alpha1.AWSECRCredential) *awsv1alpha2.ClusterAWSECRImagePullSecret {
	return &awsv1alpha2.ClusterAWSECRImagePullSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            in.Name,
			OwnerReferences: in.OwnerReferences,
			Labels:          in.Labels,
			Annotations:     in.Annotations,
			Finalizers:      in.Finalizers,
		},
		Spec: awsv1alpha2.ClusterAWSECRImagePullSecretSpec{
			AWSAccess:  in.Spec.AWSAccess,
			SecretName: in.Spec.SecretName,
			Namespaces: in.Spec.Namespaces,
		},
	}

}

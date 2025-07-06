package v1alpha2

import (
	"github.com/zak905/kube-ecr-secrets-operator/common"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AWSECRImagePullSecretSpec defines the desired state of AwsecrimagePullSecret
type AWSECRImagePullSecretSpec struct {
	//the name of the secret holding the AWS credentials that will be used to talk to AWS to get ECR credentials
	AWSAccess common.AWSAccess `json:"awsAccess,omitempty"`
	//+kubebuilder:validation:MaxLength=253
	//+kubebuilder:validation:MinLength=1
	//the name of the docker secret that will be created and updated by the operator in each of the specified namespaces
	SecretName string `json:"secretName,omitempty"`
}

// AWSECRImagePullSecretStatus defines the observed state of AwsecrimagePullSecret.
// It should always be reconstructable from the state of the cluster and/or outside world.
type AWSECRImagePullSecretStatus struct {
	//+listType=map
	//+listMapKey=type
	//+patchStrategy=merge
	//+patchMergeKey=type
	//+optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// AWSECRImagePullSecret is the Schema for the awsecrimagepullsecrets API
// +k8s:openapi-gen=true
type AWSECRImagePullSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AWSECRImagePullSecretSpec   `json:"spec,omitempty"`
	Status AWSECRImagePullSecretStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AWSECRImagePullSecretList contains a list of AwsecrimagePullSecret
type AWSECRImagePullSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AWSECRImagePullSecret `json:"items"`
}

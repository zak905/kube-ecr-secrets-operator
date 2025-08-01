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

package v1alpha1

import (
	"github.com/zak905/kube-ecr-secrets-operator/common"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// AWSECRCredentialSpec defines the desired state of AWSECRCredential
type AWSECRCredentialSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	//the name of the secret holding the AWS credentials that will be used to talk to AWS to get ECR credentials
	AWSAccess common.AWSAccess `json:"awsAccess,omitempty"`
	//+kubebuilder:validation:MaxLength=253
	//+kubebuilder:validation:MinLength=1
	//the name of the docker secret that will be created and updated by the operator in each of the specified namespaces
	SecretName string `json:"secretName,omitempty"`
	//+kubebuilder:validation:MinItems=1
	//the namespaces in which the operator will create and and manage ECR registry docker secrets
	Namespaces []string `json:"namespaces,omitempty"`
}

// AWSECRCredentialStatus defines the current status of a AWSECRCredential
type AWSECRCredentialStatus struct {
	//+listType=map
	//+listMapKey=type
	//+patchStrategy=merge
	//+patchMergeKey=type
	//+optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:resource:scope=Cluster
//+kubebuilder:subresource:status
//+kubebuilder:deprecatedversion:warning="aws.zakariaamine.com/v1alpha1 AWSECRCredential is deprecated and will be automatically converted to aws.zakariaamine.com/v1alpha2 ClusterAWSECRPullSecret"

// AWSECRCredential is the Schema for the awsecrcredentials API.
// It manages several docker secrets for AWS ECR across different namespaces.
type AWSECRCredential struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec AWSECRCredentialSpec `json:"spec,omitempty"`

	Status AWSECRCredentialStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// AWSECRCredentialList contains a list of AWSECRCredential
type AWSECRCredentialList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AWSECRCredential `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AWSECRCredential{}, &AWSECRCredentialList{})
}

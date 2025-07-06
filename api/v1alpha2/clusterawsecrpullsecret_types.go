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

package v1alpha2

import (
	"github.com/zak905/kube-ecr-secrets-operator/common"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterAWSECRImagePullSecretSpec defines the desired state of ClusterAWSECRCredentials
type ClusterAWSECRImagePullSecretSpec struct {
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

// ClusterAWSECRImagePullSecretStatus defines the observed state of ClusterAWSECRCredentials.
// It should always be reconstructable from the state of the cluster and/or outside world.
type ClusterAWSECRImagePullSecretStatus struct {
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

// ClusterAWSECRImagePullSecret is the Schema for the clusterawsecrcredentials API
type ClusterAWSECRImagePullSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterAWSECRImagePullSecretSpec   `json:"spec,omitempty"`
	Status ClusterAWSECRImagePullSecretStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ClusterAWSECRImagePullSecretList contains a list of ClusterAWSECRCredentials
type ClusterAWSECRImagePullSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterAWSECRImagePullSecret `json:"items"`
}

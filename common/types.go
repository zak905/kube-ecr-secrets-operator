package common

// AWSAccess defines the AWS access. This will be used by the operator to obtain the ECR credentials from AWS
type AWSAccess struct {
	//+kubebuilder:validation:Required
	//AWS access key associated with an IAM account that will be used to create and refresh ECR docker credentials
	AccessKeyID string `json:"accessKeyId"`
	//+kubebuilder:validation:Required
	//the secret key associated with the access key.
	SecretAccessKey string `json:"secretAccessKey"`
	//+kubebuilder:validation:Required
	//specifies the AWS Region to send the request to
	Region string `json:"region"`
}

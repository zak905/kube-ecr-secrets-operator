package controllers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/zak905/kube-ecr-secrets-operator/api/v1alpha2"
	"github.com/zak905/kube-ecr-secrets-operator/common"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	validationSuccessMsg  = "validation successful"
	invalidCredsMsg       = "aws credentials specified in .spec.awsAccess are invalid or missing permissions"
	secretExistsMsg       = "secret %s already exists in namespace %s, you can choose a different name"
	secretImmutableMsg    = ".spec.secretName is immutable"
	awsAccessImmutableMsg = ".spec.awsAccess is immutable"
)

type AWSECRCredentialValidator struct {
	Client  client.Client
	Decoder admission.Decoder
}

//+kubebuilder:webhook:path=/validate-mutate-awsecrcredential,mutating=true,admissionReviewVersions=v1;v1beta1,failurePolicy=fail,groups=aws.zakariaamine.com,resources=awsecrimagepullsecrets;clusterawsecrimagepullsecrets,verbs=create;update,versions=v1alpha2,name=ecrcredential.zakariaamine.com,sideEffects=NoneOnDryRun

func (v *AWSECRCredentialValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	kind := req.Kind.Kind
	response := admission.Allowed(validationSuccessMsg)

	if kind == "AWSECRImagePullSecret" {
		response = v.validateAWSECRImagePullSecret(ctx, req)
	} else if kind == "ClusterAWSECRImagePullSecret" {
		response = v.validateClusterAWSECRImagePullSecret(ctx, req)
	}

	return response
}

func (v *AWSECRCredentialValidator) validateAWSECRImagePullSecret(ctx context.Context, req admission.Request) admission.Response {
	var cred v1alpha2.AWSECRImagePullSecret
	err := v.Decoder.Decode(req, &cred)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	response := admission.Allowed(validationSuccessMsg)

	if req.Operation == "CREATE" {
		// check if AWS credentials are working
		awsAccess := cred.Spec.AWSAccess
		if _, err := getAWSECRAuthToken(ctx, awsAccess.AccessKeyID, awsAccess.SecretAccessKey, awsAccess.Region); err != nil {
			return admission.Denied(fmt.Sprintf("%s: %s", invalidCredsMsg,
				err.Error()))
		}

		var dockerSecret v1.Secret
		if err := v.Client.Get(ctx,
			client.ObjectKey{
				Name:      cred.Spec.SecretName,
				Namespace: cred.Namespace,
			}, &dockerSecret); err == nil {
			return admission.Denied(fmt.Sprintf(secretExistsMsg,
				cred.Spec.SecretName, cred.Namespace))
		} else if !errors.IsNotFound(err) {
			return admission.Errored(http.StatusInternalServerError, err)
		}

		//do base64 for the aws credentials, like K8 does for secrets
		cred.Spec.AWSAccess.AccessKeyID = base64.StdEncoding.EncodeToString([]byte(cred.Spec.AWSAccess.AccessKeyID))
		cred.Spec.AWSAccess.SecretAccessKey = base64.StdEncoding.EncodeToString([]byte(cred.Spec.AWSAccess.SecretAccessKey))
		marshaledCred, err := json.Marshal(cred)
		if err != nil {
			return admission.Errored(http.StatusInternalServerError, err)
		}
		response = admission.PatchResponseFromRaw(req.Object.Raw, marshaledCred)
	} else if req.Operation == "UPDATE" {
		var oldObj v1alpha2.AWSECRImagePullSecret
		if err := v.Decoder.DecodeRaw(req.OldObject, &oldObj); err != nil {
			return admission.Errored(http.StatusBadRequest, err)
		}

		var newObj v1alpha2.AWSECRImagePullSecret
		err := v.Decoder.Decode(req, &newObj)
		if err != nil {
			return admission.Errored(http.StatusBadRequest, err)
		}

		if oldObj.Spec.SecretName != newObj.Spec.SecretName {
			return admission.Denied(secretImmutableMsg)
		}

		if IsAwsAccessChanged(oldObj.Spec.AWSAccess, newObj.Spec.AWSAccess) {
			return admission.Denied(awsAccessImmutableMsg)
		}
	}

	return response
}

func (v *AWSECRCredentialValidator) validateClusterAWSECRImagePullSecret(ctx context.Context, req admission.Request) admission.Response {
	var cred v1alpha2.ClusterAWSECRImagePullSecret
	err := v.Decoder.Decode(req, &cred)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	response := admission.Allowed(validationSuccessMsg)

	if req.Operation == "CREATE" {
		// check if AWS credentials are working
		awsAccess := cred.Spec.AWSAccess
		if _, err := getAWSECRAuthToken(ctx, awsAccess.AccessKeyID, awsAccess.SecretAccessKey, awsAccess.Region); err != nil {
			return admission.Denied(fmt.Sprintf("aws credentials specified in .spec.awsAccess are invalid or missing permissions: %s",
				err.Error()))
		}

		var namespaceList v1.NamespaceList

		err = v.Client.List(ctx, &namespaceList)
		if err != nil {
			return admission.Errored(http.StatusBadRequest, fmt.Errorf("failed to list namespaces: %w", err))
		}

		for _, credNamespace := range cred.Spec.Namespaces {
			var found bool
			for _, namespace := range namespaceList.Items {
				if namespace.Name == credNamespace {
					found = true
					break
				}
			}
			if !found {
				return admission.Denied(fmt.Sprintf("namespace %s does not exist", credNamespace))
			}

			var dockerSecret v1.Secret
			if err := v.Client.Get(ctx,
				client.ObjectKey{
					Name:      cred.Spec.SecretName,
					Namespace: credNamespace,
				}, &dockerSecret); err == nil {
				return admission.Denied(fmt.Sprintf(secretExistsMsg,
					cred.Spec.SecretName, credNamespace))
			} else if !errors.IsNotFound(err) {
				return admission.Errored(http.StatusInternalServerError, err)
			}
		}
		//do base64 for the aws credentials, like K8 does for secrets
		cred.Spec.AWSAccess.AccessKeyID = base64.StdEncoding.EncodeToString([]byte(cred.Spec.AWSAccess.AccessKeyID))
		cred.Spec.AWSAccess.SecretAccessKey = base64.StdEncoding.EncodeToString([]byte(cred.Spec.AWSAccess.SecretAccessKey))
		marshaledCred, err := json.Marshal(cred)
		if err != nil {
			return admission.Errored(http.StatusInternalServerError, err)
		}
		response = admission.PatchResponseFromRaw(req.Object.Raw, marshaledCred)
	} else if req.Operation == "UPDATE" {
		var oldObj v1alpha2.ClusterAWSECRImagePullSecret
		if err := v.Decoder.DecodeRaw(req.OldObject, &oldObj); err != nil {
			return admission.Errored(http.StatusBadRequest, err)
		}

		var newObj v1alpha2.ClusterAWSECRImagePullSecret
		err := v.Decoder.Decode(req, &newObj)
		if err != nil {
			return admission.Errored(http.StatusBadRequest, err)
		}

		if oldObj.Spec.SecretName != newObj.Spec.SecretName {
			return admission.Denied(secretImmutableMsg)
		}

		if IsAwsAccessChanged(oldObj.Spec.AWSAccess, newObj.Spec.AWSAccess) {
			return admission.Denied(awsAccessImmutableMsg)
		}
	}

	return response
}

func IsAwsAccessChanged(old common.AWSAccess, new common.AWSAccess) bool {
	if old.Region != new.Region {
		return true
	}

	decodedOldAccessKeyID, err := base64.StdEncoding.DecodeString(old.AccessKeyID)
	if err != nil {
		fmt.Println(err.Error())
		return true
	}

	decodedNewAccessKeyID, err := base64.StdEncoding.DecodeString(new.AccessKeyID)
	if err != nil {
		fmt.Println(err.Error())
		return true
	}

	if string(decodedOldAccessKeyID) != string(decodedNewAccessKeyID) {
		return true
	}

	decodedOldSecretAccessKey, err := base64.StdEncoding.DecodeString(old.SecretAccessKey)
	if err != nil {
		return true
	}

	decodedNewSecretAccessKey, err := base64.StdEncoding.DecodeString(new.SecretAccessKey)
	if err != nil {
		return true
	}

	if string(decodedOldSecretAccessKey) != string(decodedNewSecretAccessKey) {
		return true
	}

	return false
}

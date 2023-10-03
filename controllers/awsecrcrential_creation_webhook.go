package controllers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"

	"github.com/zak905/kube-ecr-secrets-operator/api/v1alpha1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type AWSECRCredentialValidator struct {
	Client  client.Client
	Decoder *admission.Decoder
}

//+kubebuilder:webhook:path=/validate-mutate-awsecrcredential,mutating=true,admissionReviewVersions=v1;v1beta1,failurePolicy=fail,groups=aws.zakariaamine.com,resources=awsecrcredentials,verbs=create;update,versions=v1alpha1,name=ecrcredential.zakariaamine.com,sideEffects=NoneOnDryRun

func (v *AWSECRCredentialValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	var cred v1alpha1.AWSECRCredential
	err := v.Decoder.Decode(req, &cred)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	response := admission.Allowed("validation successful")

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
				return admission.Denied(fmt.Sprintf("secret %s already exists in namespace %s, you can choose a different name",
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
		var oldObj v1alpha1.AWSECRCredential
		if err := v.Decoder.DecodeRaw(req.OldObject, &oldObj); err != nil {
			return admission.Errored(http.StatusBadRequest, err)
		}

		var newObj v1alpha1.AWSECRCredential
		err := v.Decoder.Decode(req, &newObj)
		if err != nil {
			return admission.Errored(http.StatusBadRequest, err)
		}

		if oldObj.Spec.SecretName != newObj.Spec.SecretName {
			return admission.Denied("secretName is immutable")
		}

		if !reflect.DeepEqual(oldObj.Spec.AWSAccess, newObj.Spec.AWSAccess) {
			newObj.Spec.AWSAccess.AccessKeyID = base64.StdEncoding.EncodeToString([]byte(newObj.Spec.AWSAccess.AccessKeyID))
			newObj.Spec.AWSAccess.SecretAccessKey = base64.StdEncoding.EncodeToString([]byte(newObj.Spec.AWSAccess.SecretAccessKey))
			marshaledCred, err := json.Marshal(newObj)
			if err != nil {
				return admission.Errored(http.StatusInternalServerError, err)
			}
			response = admission.PatchResponseFromRaw(req.Object.Raw, marshaledCred)
		}
	}

	return response
}

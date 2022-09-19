package controllers

import (
	"context"
	"fmt"
	"net/http"
	"reflect"

	"github.com/zak905/kube-ecr-secrets-operator/api/v1alpha1"
	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type AWSECRCredentialValidator struct {
	Client  client.Client
	decoder *admission.Decoder
}

//+kubebuilder:webhook:path=/validate-awsecrcredential,mutating=false,admissionReviewVersions=v1;v1beta1,failurePolicy=fail,groups=aws.zakariaamine.com,resources=awsecrcredentials,verbs=create;update,versions=v1alpha1,name=ecrcredential.aws.zakariaamine.com,sideEffects=None

func (v *AWSECRCredentialValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	var cred v1alpha1.AWSECRCredential
	err := v.decoder.Decode(req, &cred)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	if req.Operation == "CREATE" {
		var awsCredentialsSecret v1.Secret
		if err := v.Client.Get(ctx,
			client.ObjectKey{
				Name:      cred.Spec.AWSAccess.SecretName,
				Namespace: cred.Spec.AWSAccess.Namespace,
			}, &awsCredentialsSecret); err != nil {
			return admission.Denied(fmt.Sprintf("secret %s not found in namespace %s",
				cred.Spec.AWSAccess.SecretName, cred.Spec.AWSAccess.Namespace))
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
				return admission.Denied(fmt.Sprintf("secret %s already exists in namespace %s, choose a different name",
					cred.Spec.SecretName, credNamespace))
			}
		}
	} else if req.Operation == "UPDATE" {
		var oldObj v1alpha1.AWSECRCredential
		if err := v.decoder.DecodeRaw(req.OldObject, &oldObj); err != nil {
			return admission.Errored(http.StatusBadRequest, err)
		}

		var newObj v1alpha1.AWSECRCredential
		err := v.decoder.Decode(req, &newObj)
		if err != nil {
			return admission.Errored(http.StatusBadRequest, err)
		}

		if oldObj.Spec.SecretName != newObj.Spec.SecretName {
			return admission.Denied("secretName is immutable")
		}

		if !reflect.DeepEqual(oldObj.Spec.AWSAccess, newObj.Spec.AWSAccess) {
			return admission.Denied("awsAccess is immutable")
		}
	}

	return admission.Allowed("validation successful")
}

func (v *AWSECRCredentialValidator) InjectDecoder(d *admission.Decoder) error {
	v.decoder = d
	return nil
}

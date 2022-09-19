package controllers

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/zak905/kube-ecr-secrets-operator/api/v1alpha1"
	v1 "k8s.io/api/core/v1"
	apiErrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type SecretsWatcher struct {
	Client  client.Client
	decoder *admission.Decoder
}

//+kubebuilder:webhook:path=/validate-secret-delete,admissionReviewVersions=v1;v1beta1,mutating=true,failurePolicy=fail,groups="",resources=secrets,verbs=delete,versions=v1,name=secret.aws.zakariaamine.com,sideEffects=NoneOnDryRun

func (w *SecretsWatcher) Handle(ctx context.Context, req admission.Request) admission.Response {
	var secret v1.Secret
	if err := w.decoder.DecodeRaw(req.OldObject, &secret); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	for _, ownerRef := range secret.OwnerReferences {
		//secret is managed by the operator
		if ownerRef.Kind == "AWSECRCredential" {
			var ecrCredential v1alpha1.AWSECRCredential

			if err := w.Client.Get(ctx, client.ObjectKey{Name: ownerRef.Name}, &ecrCredential); err != nil {
				statusErr, ok := err.(*apiErrors.StatusError)
				if !ok {
					return admission.Errored(http.StatusBadRequest, errors.New("could not process API error"))
				}

				if statusErr.ErrStatus.Code == http.StatusNotFound {
					return admission.Allowed("safe to delete secret")
				}

				return admission.Errored(http.StatusBadRequest, err)
			}

			return admission.Denied(
				fmt.Sprintf(
					"secret is managed by AWSECRCrendentials Object with name %s, and cannot be delete manually, delete parent object",
					ecrCredential.Name,
				),
			)
		}
	}

	return admission.Allowed("safe to delete secret")
}

func (w *SecretsWatcher) InjectDecoder(d *admission.Decoder) error {
	w.decoder = d
	return nil
}

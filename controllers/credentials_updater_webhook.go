package controllers

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
	v1 "k8s.io/api/core/v1"
	apiErrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/zak905/kube-ecr-secrets-operator/api/v1alpha1"
)

type DockerCredentialsReferesher struct {
	Client  client.Client
	Decoder *admission.Decoder
}

//TODO: remove this is deprecated, and not used anymore

// This handler does not reject the request no matter what happens
// this would prevent the pod update/creation
// it attempts to update the credentials, and logs if there is an error
func (r *DockerCredentialsReferesher) Handle(ctx context.Context, req admission.Request) admission.Response {
	log := log.FromContext(ctx)
	pod := &v1.Pod{}
	err := r.Decoder.Decode(req, pod)
	if err != nil {
		log.Error(err, "unable to decode the pod object from the webhook payload")
	}

	for _, pullSecretRef := range pod.Spec.ImagePullSecrets {
		log.Info("looking for secret ",
			zap.String("secret", pullSecretRef.Name), zap.String("pod_name", pod.Name), zap.String("namespace", pod.Namespace))
		var pullSecret v1.Secret
		if err := r.Client.Get(ctx,
			client.ObjectKey{
				Name:      pullSecretRef.Name,
				Namespace: pod.Namespace,
			}, &pullSecret); err != nil {
			if apiErrors.IsNotFound(err) {
				if err := r.createSecretIfMatches(ctx, pod.Namespace, pullSecretRef.Name); err != nil {
					log.Error(err, "unable to create the missing secret", zap.String("secret", pullSecretRef.Name),
						zap.String("pod_name", pod.Name), zap.String("namespace", pod.Namespace))
				}
			}
		} else {
			log.Info("secret found, checking reference",
				zap.String("secret", pullSecretRef.Name), zap.String("pod_name", pod.Name), zap.String("namespace", pod.Namespace))

			// try owner references first
			var found bool
			for _, ownerRef := range pullSecret.OwnerReferences {
				// secret is managed by the operator
				if ownerRef.Kind == "AWSECRCredential" {
					var ecrCredential v1alpha1.AWSECRCredential

					if err := r.Client.Get(ctx, client.ObjectKey{Name: ownerRef.Name}, &ecrCredential); err != nil {
						log.Error(err, "unable to get AWSECRCredential", zap.String("AWSECRCredential", ownerRef.Name),
							zap.String("secret", pullSecretRef.Name), zap.String("pod_name", pod.Name), zap.String("namespace", pod.Namespace))
					}

					expiry, err := time.Parse(time.RFC3339, pullSecret.Annotations["expiry"])
					if err != nil || expiry.Before(time.Now().UTC()) {
						dockerConfig, expiresAt, err := getDockerJSONConfigFromAWS(ctx, ecrCredential.Spec.AWSAccess)
						if err != nil {
							log.Error(err, "unable to get docker secret from AWS",
								zap.String("secret", pullSecretRef.Name), zap.String("pod_name", pod.Name), zap.String("namespace", pod.Namespace))
						}

						log.Info("updating docker secret")
						pullSecret.Data[".dockerconfigjson"] = dockerConfig
						pullSecret.Annotations[expiryAnnotation] = expiresAt.Format(time.RFC3339)
						if err := r.Client.Update(ctx, &pullSecret); err != nil {
							log.Error(err, "unable to update existing secret",
								zap.String("secret", pullSecretRef.Name), zap.String("pod_name", pod.Name), zap.String("namespace", pod.Namespace))
						}

						log.Info("docker secret updated",
							zap.String("secret", pullSecretRef.Name), zap.String("pod_name", pod.Name), zap.String("namespace", pod.Namespace))
					}
					found = true
					break
				}
			}
			// if not found using owner References, owner references should be there in principle
			// but just in case
			if !found {
				if err := r.createSecretIfMatches(ctx, pod.Namespace, pullSecret.Name); err != nil {
					log.Info("unable to create the missing secret",
						zap.String("secret", pullSecretRef.Name), zap.String("pod_name", pod.Name))
				}
			}
		}

	}

	return admission.Allowed("ecr credentials updated successfully")
}

// TODO: remove this when uprading to 1.21 in favor of the new slice package
func sliceContains(items []string, s string) bool {
	for _, item := range items {
		if item == s {
			return true
		}
	}

	return false
}

// creates a secret if it matches referenceSecretName and there is an AWSECRCredential present in the namespace
func (r *DockerCredentialsReferesher) createSecretIfMatches(ctx context.Context, namespace, referenceSecretName string) error {
	ecrCredentialsList := &v1alpha1.AWSECRCredentialList{}
	if err := r.Client.List(ctx, ecrCredentialsList); err != nil {
		return fmt.Errorf("unable to list AWSECRCredential CRDs in the cluster: %w", err)
	}

	for _, ecrCredential := range ecrCredentialsList.Items {
		if sliceContains(ecrCredential.Spec.Namespaces, namespace) && ecrCredential.Spec.SecretName == referenceSecretName {
			dockerConfig, expiresAt, err := getDockerJSONConfigFromAWS(ctx, ecrCredential.Spec.AWSAccess)
			if err != nil {
				return fmt.Errorf("unable to get Docker credentials from AWS: %w", err)
			}

			if err := r.Client.Create(ctx, newDockerSecret(ctx, &ecrCredential, dockerConfig, expiresAt)); err != nil {
				return fmt.Errorf("unable to get Docker credentials from AWS: %w", err)
			}
		}
	}

	return nil
}

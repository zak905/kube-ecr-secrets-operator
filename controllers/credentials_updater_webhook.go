package controllers

import (
	"context"
	"net/http"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/zak905/kube-ecr-secrets-operator/api/v1alpha1"
)

type DockerCredentialsReferesher struct {
	Client  client.Client
	decoder *admission.Decoder
}

//+kubebuilder:webhook:path=/mutate-v1-pod,admissionReviewVersions=v1;v1beta1,mutating=true,failurePolicy=fail,groups="",resources=pods,verbs=create;update,versions=v1,name=awsecrcredential.zakariaamine.com,sideEffects=NoneOnDryRun

func (r *DockerCredentialsReferesher) Handle(ctx context.Context, req admission.Request) admission.Response {
	log := log.FromContext(ctx)
	pod := &v1.Pod{}
	err := r.decoder.Decode(req, pod)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	for _, pullSecretRef := range pod.Spec.ImagePullSecrets {
		log.Info("looking for secret " + pullSecretRef.Name)
		var pullSecret v1.Secret
		if err := r.Client.Get(ctx,
			client.ObjectKey{
				Name:      pullSecretRef.Name,
				Namespace: pod.Namespace,
			}, &pullSecret); err != nil {
			return admission.Errored(http.StatusBadRequest, err)
		}

		log.Info("secret " + pullSecretRef.Name + " found, checking reference")

		for _, ownerRef := range pullSecret.OwnerReferences {
			//secret is managed by the operator
			if ownerRef.Kind == "AWSECRCredential" {
				var ecrCredential v1alpha1.AWSECRCredential

				if err := r.Client.Get(ctx, client.ObjectKey{Name: ownerRef.Name}, &ecrCredential); err != nil {
					return admission.Errored(http.StatusBadRequest, err)
				}

				log.Info("found parent " + ecrCredential.Name + ",getting AWS secret")

				var awsAccessSecret v1.Secret
				if err := r.Client.Get(ctx,
					client.ObjectKey{
						Name:      ecrCredential.Spec.AWSAccess.SecretName,
						Namespace: ecrCredential.Spec.AWSAccess.Namespace,
					}, &awsAccessSecret); err != nil {
					return admission.Errored(http.StatusBadRequest, err)
				}

				expiry, err := time.Parse(time.RFC3339, pullSecret.Annotations["expiry"])
				if err != nil || expiry.Before(time.Now().UTC()) {
					dockerConfig, expiresAt, err := createDockerJSONConfig(ctx, awsAccessSecret.Data)
					if err != nil {
						return admission.Errored(http.StatusBadRequest, err)
					}

					log.Info("updating docker secret")

					dockerSecret := v1.Secret{
						Type: v1.SecretTypeDockerConfigJson,
						ObjectMeta: metav1.ObjectMeta{
							Name:      pullSecret.Name,
							Namespace: pullSecret.Namespace,
							Annotations: map[string]string{
								expiryAnnotation: expiresAt.Format(time.RFC3339),
							},
							OwnerReferences: []metav1.OwnerReference{
								{
									APIVersion: ecrCredential.APIVersion,
									Kind:       ecrCredential.Kind,
									UID:        ecrCredential.GetUID(),
									Name:       ecrCredential.Name,
								},
							},
						},
						Data: map[string][]byte{".dockerconfigjson": dockerConfig},
					}

					if err := r.Client.Update(ctx, &dockerSecret); err != nil {
						return admission.Errored(http.StatusBadRequest, err)
					}

					log.Info("docker secret updated")
				}
				break
			}
		}
	}

	return admission.Allowed("ecr credentials updated successfully")
}

func (r *DockerCredentialsReferesher) InjectDecoder(d *admission.Decoder) error {
	r.decoder = d
	return nil
}

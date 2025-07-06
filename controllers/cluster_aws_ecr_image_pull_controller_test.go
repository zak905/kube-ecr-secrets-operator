package controllers

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	machineryErrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	awsv1alpha2 "github.com/zak905/kube-ecr-secrets-operator/api/v1alpha2"
	"github.com/zak905/kube-ecr-secrets-operator/common"
	corev1 "k8s.io/api/core/v1"
	//+kubebuilder:scaffold:imports
)

var _ = Describe("ClusterAWSECRImagePullSecret", func() {
	It("creation fails if AWS credentials are invalid", func(ctx context.Context) {
		awsCredential := awsv1alpha2.ClusterAWSECRImagePullSecret{
			ObjectMeta: v1.ObjectMeta{
				Name: "cred",
			},
			Spec: awsv1alpha2.ClusterAWSECRImagePullSecretSpec{
				AWSAccess: common.AWSAccess{},
			},
		}

		err := k8sClient.Create(ctx, &awsCredential)
		Expect(err).To(HaveOccurred())
		statusErr := &machineryErrors.StatusError{}
		Expect(errors.As(err, &statusErr)).To(BeTrue())
		Expect(statusErr.Status().Reason).To(Equal(v1.StatusReasonForbidden))
		Expect(statusErr.Status().Message).To(ContainSubstring(invalidCredsMsg))
	})

	It("creation fails if a namespace does not exist", func(ctx context.Context) {
		inexistingNamespace := "inexisting"
		awsCredential := awsv1alpha2.ClusterAWSECRImagePullSecret{
			ObjectMeta: v1.ObjectMeta{
				Name: "cred",
			},
			Spec: awsv1alpha2.ClusterAWSECRImagePullSecretSpec{
				AWSAccess: common.AWSAccess{
					AccessKeyID:     testConfig.AWSAccessKeyID,
					SecretAccessKey: testConfig.AWSSecretAccessKey,
					Region:          testConfig.AWSRegion,
				},
				Namespaces: []string{inexistingNamespace},
			},
		}

		err := k8sClient.Create(ctx, &awsCredential)
		Expect(err).To(HaveOccurred())
		statusErr := &machineryErrors.StatusError{}
		Expect(errors.As(err, &statusErr)).To(BeTrue())
		Expect(statusErr.Status().Reason).To(Equal(v1.StatusReasonForbidden))
		Expect(statusErr.Status().Message).To(ContainSubstring(fmt.Sprintf("namespace %s does not exist", inexistingNamespace)))
	})

	It("creation fails if secret with the same name exists in the namespace", func(ctx context.Context) {
		namespaceName := fmt.Sprintf("ns%d", time.Now().UnixMilli())
		secretName := "secret"
		Expect(k8sClient.Create(ctx, &corev1.Namespace{
			ObjectMeta: v1.ObjectMeta{
				Name: namespaceName,
			},
		})).To(Succeed())

		Expect(k8sClient.Create(ctx, &corev1.Secret{
			ObjectMeta: v1.ObjectMeta{
				Name:      secretName,
				Namespace: namespaceName,
			},
		})).To(Succeed())

		awsCredential := awsv1alpha2.ClusterAWSECRImagePullSecret{
			ObjectMeta: v1.ObjectMeta{
				Name: "cred",
			},
			Spec: awsv1alpha2.ClusterAWSECRImagePullSecretSpec{
				AWSAccess: common.AWSAccess{
					AccessKeyID:     testConfig.AWSAccessKeyID,
					SecretAccessKey: testConfig.AWSSecretAccessKey,
					Region:          testConfig.AWSRegion,
				},
				SecretName: secretName,
				Namespaces: []string{namespaceName},
			},
		}

		err := k8sClient.Create(ctx, &awsCredential)
		Expect(err).To(HaveOccurred())
		statusErr := &machineryErrors.StatusError{}
		Expect(errors.As(err, &statusErr)).To(BeTrue())
		Expect(statusErr.Status().Reason).To(Equal(v1.StatusReasonForbidden))
		Expect(statusErr.Status().Message).To(ContainSubstring(fmt.Sprintf(secretExistsMsg, secretName, namespaceName)))
	})

	It("creation success", func(ctx context.Context) {
		timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())
		namespaces := []string{"ns1" + timestamp, "ns2" + timestamp, "ns3" + timestamp}

		for _, ns := range namespaces {
			Expect(k8sClient.Create(ctx, &corev1.Namespace{
				ObjectMeta: v1.ObjectMeta{
					Name: ns,
				},
			})).To(Succeed())
		}

		secretName := "secret"

		awsCredential := awsv1alpha2.ClusterAWSECRImagePullSecret{
			ObjectMeta: v1.ObjectMeta{
				Name: "cred" + timestamp,
			},
			Spec: awsv1alpha2.ClusterAWSECRImagePullSecretSpec{
				AWSAccess: common.AWSAccess{
					AccessKeyID:     testConfig.AWSAccessKeyID,
					SecretAccessKey: testConfig.AWSSecretAccessKey,
					Region:          testConfig.AWSRegion,
				},
				SecretName: secretName,
				Namespaces: namespaces,
			},
		}

		Expect(k8sClient.Create(ctx, &awsCredential)).To(Succeed())
		Expect(awsCredential.Spec.AWSAccess.AccessKeyID).To(Equal(base64.StdEncoding.EncodeToString([]byte(testConfig.AWSAccessKeyID))))
		Expect(awsCredential.Spec.AWSAccess.SecretAccessKey).To(Equal(base64.StdEncoding.EncodeToString([]byte(testConfig.AWSSecretAccessKey))))
		for _, ns := range namespaces {
			secret := &corev1.Secret{}
			Eventually(func() error {
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: secretName, Namespace: ns}, secret); err != nil {
					return err
				}
				if secret.Type != corev1.SecretTypeDockerConfigJson {
					return errors.New("secret type is not kubernetes.io/dockerconfigjson")
				}
				return nil
			}, "10s", "2s")
		}

		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: awsCredential.Name}, &awsCredential)).To(Succeed())
			g.Expect(awsCredential.Status.Conditions).To(HaveLen(1))
			g.Expect(awsCredential.Status.Conditions[0].Type).To(Equal(ReadyCondition))
			g.Expect(awsCredential.Status.Conditions[0].Reason).To(Equal(SecretsUpdatedReason))
			g.Expect(awsCredential.Status.Conditions[0].Status).To(Equal(v1.ConditionTrue))
		}, "10s", "2s")

	})

	It("update fails if new spec have different secretName", func(ctx context.Context) {
		timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())
		namespaces := []string{"ns1" + timestamp, "ns2" + timestamp}

		for _, ns := range namespaces {
			Expect(k8sClient.Create(ctx, &corev1.Namespace{
				ObjectMeta: v1.ObjectMeta{
					Name: ns,
				},
			})).To(Succeed())
		}

		secretName := "secret"

		awsCredential := awsv1alpha2.ClusterAWSECRImagePullSecret{
			ObjectMeta: v1.ObjectMeta{
				Name: "cred" + timestamp,
			},
			Spec: awsv1alpha2.ClusterAWSECRImagePullSecretSpec{
				AWSAccess: common.AWSAccess{
					AccessKeyID:     testConfig.AWSAccessKeyID,
					SecretAccessKey: testConfig.AWSSecretAccessKey,
					Region:          testConfig.AWSRegion,
				},
				SecretName: secretName,
				Namespaces: namespaces,
			},
		}

		Expect(k8sClient.Create(ctx, &awsCredential)).To(Succeed())

		awsCredential.Spec.SecretName = "newSecretName"
		err := k8sClient.Update(ctx, &awsCredential)
		Expect(err).To(HaveOccurred())
		statusErr := &machineryErrors.StatusError{}
		Expect(errors.As(err, &statusErr)).To(BeTrue())
		Expect(statusErr.Status().Reason).To(Equal(v1.StatusReasonForbidden))
		Expect(statusErr.Status().Message).To(ContainSubstring(secretImmutableMsg))
	})

	It("update fails if new spec have differenr awsAccess", func(ctx context.Context) {
		timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())
		namespaces := []string{"ns1" + timestamp, "ns2" + timestamp}

		for _, ns := range namespaces {
			Expect(k8sClient.Create(ctx, &corev1.Namespace{
				ObjectMeta: v1.ObjectMeta{
					Name: ns,
				},
			})).To(Succeed())
		}

		secretName := "secret"

		awsCredential := awsv1alpha2.ClusterAWSECRImagePullSecret{
			ObjectMeta: v1.ObjectMeta{
				Name: "cred" + timestamp,
			},
			Spec: awsv1alpha2.ClusterAWSECRImagePullSecretSpec{
				AWSAccess: common.AWSAccess{
					AccessKeyID:     testConfig.AWSAccessKeyID,
					SecretAccessKey: testConfig.AWSSecretAccessKey,
					Region:          testConfig.AWSRegion,
				},
				SecretName: secretName,
				Namespaces: namespaces,
			},
		}

		Expect(k8sClient.Create(ctx, &awsCredential)).To(Succeed())

		awsCredential.Spec.AWSAccess.AccessKeyID = "newAccessKeyId"
		err := k8sClient.Update(ctx, &awsCredential)
		Expect(err).To(HaveOccurred())
		statusErr := &machineryErrors.StatusError{}
		Expect(errors.As(err, &statusErr)).To(BeTrue())
		Expect(statusErr.Status().Reason).To(Equal(v1.StatusReasonForbidden))
		Expect(statusErr.Status().Message).To(ContainSubstring(awsAccessImmutableMsg))
	})

	It("update succeeds", func(ctx context.Context) {
		timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())
		namespaces := []string{"ns1" + timestamp, "ns2" + timestamp}

		for _, ns := range namespaces {
			Expect(k8sClient.Create(ctx, &corev1.Namespace{
				ObjectMeta: v1.ObjectMeta{
					Name: ns,
				},
			})).To(Succeed())
		}

		secretName := "secret"

		awsCredential := awsv1alpha2.ClusterAWSECRImagePullSecret{
			ObjectMeta: v1.ObjectMeta{
				Name: "cred" + timestamp,
			},
			Spec: awsv1alpha2.ClusterAWSECRImagePullSecretSpec{
				AWSAccess: common.AWSAccess{
					AccessKeyID:     testConfig.AWSAccessKeyID,
					SecretAccessKey: testConfig.AWSSecretAccessKey,
					Region:          testConfig.AWSRegion,
				},
				SecretName: secretName,
				Namespaces: namespaces,
			},
		}

		Expect(k8sClient.Create(ctx, &awsCredential)).To(Succeed())

		newNamespace := "newNs" + timestamp

		Expect(k8sClient.Create(ctx, &corev1.Namespace{
			ObjectMeta: v1.ObjectMeta{
				Name: newNamespace,
			},
		}))

		awsCredential.Spec.Namespaces = append(awsCredential.Spec.Namespaces, "newNs"+timestamp)
		Expect(k8sClient.Update(ctx, &awsCredential)).To(Succeed())
		Eventually(func(g Gomega) {
			secret := &corev1.Secret{}
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: secretName, Namespace: newNamespace}, secret)).
				To(Succeed())
			g.Expect(secret.Type).To(Equal(corev1.SecretTypeDockerConfigJson))
		}, "10s", "2s")
	})
})

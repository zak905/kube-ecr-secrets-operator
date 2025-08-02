package controllers

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	awsv1alpha2 "github.com/zak905/kube-ecr-secrets-operator/api/v1alpha2"
	"github.com/zak905/kube-ecr-secrets-operator/common"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	machineryErrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	corev1 "k8s.io/api/core/v1"
	//+kubebuilder:scaffold:imports
)

var _ = Describe("AWSECRImagePullSecret", func() {
	It("creation fails if AWS credentials are invalid", func(ctx context.Context) {
		awsCredential := awsv1alpha2.AWSECRImagePullSecret{
			ObjectMeta: v1.ObjectMeta{
				Name:      "cred",
				Namespace: corev1.NamespaceDefault,
			},
			Spec: awsv1alpha2.AWSECRImagePullSecretSpec{
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

		awsCredential := awsv1alpha2.AWSECRImagePullSecret{
			ObjectMeta: v1.ObjectMeta{
				Name:      "cred",
				Namespace: namespaceName,
			},
			Spec: awsv1alpha2.AWSECRImagePullSecretSpec{
				AWSAccess: common.AWSAccess{
					AccessKeyID:     testConfig.AWSAccessKeyID,
					SecretAccessKey: testConfig.AWSSecretAccessKey,
					Region:          testConfig.AWSRegion,
				},
				SecretName: secretName,
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

		secretName := "secret" + timestamp

		awsCredential := awsv1alpha2.AWSECRImagePullSecret{
			ObjectMeta: v1.ObjectMeta{
				Name:      "cred" + timestamp,
				Namespace: corev1.NamespaceDefault,
			},
			Spec: awsv1alpha2.AWSECRImagePullSecretSpec{
				AWSAccess: common.AWSAccess{
					AccessKeyID:     testConfig.AWSAccessKeyID,
					SecretAccessKey: testConfig.AWSSecretAccessKey,
					Region:          testConfig.AWSRegion,
				},
				SecretName: secretName,
			},
		}

		Expect(k8sClient.Create(ctx, &awsCredential)).To(Succeed())
		Expect(awsCredential.Spec.AWSAccess.AccessKeyID).To(Equal(base64.StdEncoding.EncodeToString([]byte(testConfig.AWSAccessKeyID))))
		Expect(awsCredential.Spec.AWSAccess.SecretAccessKey).To(Equal(base64.StdEncoding.EncodeToString([]byte(testConfig.AWSSecretAccessKey))))

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

		secretName := "secret" + timestamp

		awsCredential := awsv1alpha2.AWSECRImagePullSecret{
			ObjectMeta: v1.ObjectMeta{
				Name:      "cred" + timestamp,
				Namespace: corev1.NamespaceDefault,
			},
			Spec: awsv1alpha2.AWSECRImagePullSecretSpec{
				AWSAccess: common.AWSAccess{
					AccessKeyID:     testConfig.AWSAccessKeyID,
					SecretAccessKey: testConfig.AWSSecretAccessKey,
					Region:          testConfig.AWSRegion,
				},
				SecretName: secretName,
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

	It("update fails if new spec have different awsAccess", func(ctx context.Context) {
		timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())
		namespaces := []string{"ns1" + timestamp, "ns2" + timestamp}

		for _, ns := range namespaces {
			Expect(k8sClient.Create(ctx, &corev1.Namespace{
				ObjectMeta: v1.ObjectMeta{
					Name: ns,
				},
			})).To(Succeed())
		}

		secretName := "secret" + timestamp

		awsCredential := awsv1alpha2.AWSECRImagePullSecret{
			ObjectMeta: v1.ObjectMeta{
				Name:      "cred" + timestamp,
				Namespace: corev1.NamespaceDefault,
			},
			Spec: awsv1alpha2.AWSECRImagePullSecretSpec{
				AWSAccess: common.AWSAccess{
					AccessKeyID:     testConfig.AWSAccessKeyID,
					SecretAccessKey: testConfig.AWSSecretAccessKey,
					Region:          testConfig.AWSRegion,
				},
				SecretName: secretName,
			},
		}

		Expect(k8sClient.Create(ctx, &awsCredential)).To(Succeed())

		awsCredential.Spec.AWSAccess.AccessKeyID = "new"
		err := k8sClient.Update(ctx, &awsCredential)
		Expect(err).To(HaveOccurred())
		statusErr := &machineryErrors.StatusError{}
		Expect(errors.As(err, &statusErr)).To(BeTrue())
		Expect(statusErr.Status().Reason).To(Equal(v1.StatusReasonForbidden))
		Expect(statusErr.Status().Message).To(ContainSubstring(awsAccessImmutableMsg))
	})
})

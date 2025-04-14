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

package controllers

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	machineryErrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/caarlos0/env/v9"
	awsv1alpha1 "github.com/zak905/kube-ecr-secrets-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	//+kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var k8sClient client.Client
var testEnv *envtest.Environment
var managerCtx context.Context
var cancelFunc context.CancelFunc
var testConfig = &TestConfig{}

type TestConfig struct {
	AWSAccessKeyID     string `env:"AWS_ACCESS_KEY_ID,required"`
	AWSSecretAccessKey string `env:"AWS_SECRET_ACCESS_KEY,required"`
	AWSRegion          string `env:"AWS_REGION,required"`
}

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Controller Suite")
}

var _ = BeforeSuite(func() {
	Expect(env.Parse(testConfig)).To(Succeed())
	// inspired from https://www.infracloud.io/blogs/testing-kubernetes-operator-envtest/
	managerCtx, cancelFunc = context.WithCancel(context.TODO())

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "chart", "crds")},
		ErrorIfCRDPathMissing: true,
		WebhookInstallOptions: envtest.WebhookInstallOptions{
			Paths: []string{filepath.Join("..", "chart", "templates", "validating-webhook-config.yaml")},
		},
	}

	cfg, err := testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	err = awsv1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	//+kubebuilder:scaffold:scheme

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme.Scheme,
		WebhookServer: webhook.NewServer(webhook.Options{
			Host:    testEnv.WebhookInstallOptions.LocalServingHost,
			Port:    testEnv.WebhookInstallOptions.LocalServingPort,
			CertDir: testEnv.WebhookInstallOptions.LocalServingCertDir,
		}),
		LeaderElection: false,
	})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	Expect((&AWSECRCredentialReconciler{Client: mgr.GetClient(), Recorder: mgr.GetEventRecorderFor("aws-ecr-controller")}).
		SetupWithManager(mgr)).To(Succeed())

	mgr.GetWebhookServer().Register("/validate-mutate-awsecrcredential",
		&webhook.Admission{
			Handler: &AWSECRCredentialValidator{
				Client:  mgr.GetClient(),
				Decoder: admission.NewDecoder(mgr.GetScheme()),
			},
		},
	)

	go func() {
		//defer GinkgoRecover()
		Expect(mgr.Start(managerCtx)).To(Succeed())
	}()
})

var _ = Describe("AWSECRCredential", func() {
	It("creation fails if AWS credentials are invalid", func(ctx context.Context) {
		awsCredential := awsv1alpha1.AWSECRCredential{
			ObjectMeta: v1.ObjectMeta{
				Name: "cred",
			},
			Spec: awsv1alpha1.AWSECRCredentialSpec{
				AWSAccess: awsv1alpha1.AWSAccess{},
			},
		}

		err := k8sClient.Create(ctx, &awsCredential)
		Expect(err).To(HaveOccurred())
		statusErr := &machineryErrors.StatusError{}
		Expect(errors.As(err, &statusErr)).To(BeTrue())
		Expect(statusErr.Status().Reason).To(Equal(v1.StatusReasonForbidden))
		Expect(statusErr.Status().Message).To(ContainSubstring("aws credentials specified in .spec.awsAccess are invalid or missing permissions"))
	})

	It("creation fails if a namespace does not exist", func(ctx context.Context) {
		inexistingNamespace := "inexisting"
		awsCredential := awsv1alpha1.AWSECRCredential{
			ObjectMeta: v1.ObjectMeta{
				Name: "cred",
			},
			Spec: awsv1alpha1.AWSECRCredentialSpec{
				AWSAccess: awsv1alpha1.AWSAccess{
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

		awsCredential := awsv1alpha1.AWSECRCredential{
			ObjectMeta: v1.ObjectMeta{
				Name: "cred",
			},
			Spec: awsv1alpha1.AWSECRCredentialSpec{
				AWSAccess: awsv1alpha1.AWSAccess{
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
		Expect(statusErr.Status().Message).To(ContainSubstring(fmt.Sprintf("secret %s already exists in namespace %s, you can choose a different name", secretName, namespaceName)))
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

		awsCredential := awsv1alpha1.AWSECRCredential{
			ObjectMeta: v1.ObjectMeta{
				Name: "cred" + timestamp,
			},
			Spec: awsv1alpha1.AWSECRCredentialSpec{
				AWSAccess: awsv1alpha1.AWSAccess{
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

		awsCredential := awsv1alpha1.AWSECRCredential{
			ObjectMeta: v1.ObjectMeta{
				Name: "cred" + timestamp,
			},
			Spec: awsv1alpha1.AWSECRCredentialSpec{
				AWSAccess: awsv1alpha1.AWSAccess{
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
		Expect(statusErr.Status().Message).To(ContainSubstring("secretName is immutable"))
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

		awsCredential := awsv1alpha1.AWSECRCredential{
			ObjectMeta: v1.ObjectMeta{
				Name: "cred" + timestamp,
			},
			Spec: awsv1alpha1.AWSECRCredentialSpec{
				AWSAccess: awsv1alpha1.AWSAccess{
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
		secret := &corev1.Secret{}
		Eventually(func() error {
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: secretName, Namespace: newNamespace}, secret); err != nil {
				return err
			}
			if secret.Type != corev1.SecretTypeDockerConfigJson {
				return errors.New("secret type is not kubernetes.io/dockerconfigjson")
			}
			return nil
		}, "10s", "2s")
	})
})

var _ = AfterSuite(func() {
	cancelFunc()
	// make sure manager context is done
	<-managerCtx.Done()
	By("tearing down the test environment")
	Expect(testEnv.Stop()).To(Succeed())
})

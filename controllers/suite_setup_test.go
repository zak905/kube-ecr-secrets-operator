package controllers

import (
	"context"
	"path/filepath"
	"testing"

	awsv1alpha1 "github.com/zak905/kube-ecr-secrets-operator/api/v1alpha1"
	awsv1alpha2 "github.com/zak905/kube-ecr-secrets-operator/api/v1alpha2"

	"github.com/caarlos0/env/v9"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
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

func TestControllers(t *testing.T) {
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
			Paths: []string{filepath.Join("..", "hack", "unit-test")},
		},
		//AttachControlPlaneOutput: true,
	}

	cfg, err := testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	err = awsv1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	err = awsv1alpha2.AddToScheme(scheme.Scheme)
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

	Expect((&AWSECRCredentialReconciler{
		Client: mgr.GetClient(), Recorder: mgr.GetEventRecorderFor("test-awsecrcredential-controller")}).
		SetupWithManager(mgr)).To(Succeed())

	Expect((&GenericAWSECRPullSecretReconciler[awsv1alpha2.AWSECRImagePullSecret]{
		Client: mgr.GetClient(), Recorder: mgr.GetEventRecorderFor("test-awsecrimagepullsecret-controller")}).
		SetupWithManager(mgr)).To(Succeed())

	Expect((&GenericAWSECRPullSecretReconciler[awsv1alpha2.ClusterAWSECRImagePullSecret]{
		Client: mgr.GetClient(), Recorder: mgr.GetEventRecorderFor("test-clusterawsecrimagepullsecret-controller")}).
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

var _ = AfterSuite(func() {
	cancelFunc()
	// make sure manager context is done
	<-managerCtx.Done()
	By("tearing down the test environment")
	Expect(testEnv.Stop()).To(Succeed())
})

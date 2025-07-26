package controllers

import (
	"context"
	"errors"
	"fmt"
	"time"

	awsv1alpha1 "github.com/zak905/kube-ecr-secrets-operator/api/v1alpha1"
	awsv1alpha2 "github.com/zak905/kube-ecr-secrets-operator/api/v1alpha2"
	"github.com/zak905/kube-ecr-secrets-operator/common"
	"sigs.k8s.io/controller-runtime/pkg/client"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	machineryErrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("AWSECRCredential", func() {
	It("deprecated v1alpha1/AWSECRCredential is converted to v1alpha2/AWSECRImagePullSecret", func(ctx context.Context) {
		name := fmt.Sprintf("cred-%d", time.Now().UnixMilli())

		awsCredential := awsv1alpha1.AWSECRCredential{
			ObjectMeta: v1.ObjectMeta{
				Name: name,
			},
			Spec: awsv1alpha1.AWSECRCredentialSpec{
				AWSAccess: common.AWSAccess{},
			},
		}

		Expect(k8sClient.Create(ctx, &awsCredential)).To(Succeed())

		Eventually(ctx, func(g Gomega) {
			deprecated := &awsv1alpha1.AWSECRCredential{}
			err := k8sClient.Get(ctx, client.ObjectKey{Name: name}, deprecated)
			g.Expect(err).To(HaveOccurred())
			statusErr := &machineryErrors.StatusError{}
			g.Expect(errors.As(err, &statusErr)).To(BeTrue())
			g.Expect(statusErr.Status().Reason).To(Equal(v1.StatusReasonNotFound))
			converted := &awsv1alpha2.ClusterAWSECRImagePullSecret{}
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, deprecated)).To(Succeed())
			g.Expect(converted.Name).To(Equal(deprecated.Name))
			g.Expect(converted.Spec.SecretName).To(Equal(deprecated.Spec.SecretName))
			g.Expect(converted.Spec.AWSAccess).To(Equal(deprecated.Spec.AWSAccess))
			g.Expect(converted.Spec.Namespaces).To(Equal(deprecated.Spec.Namespaces))
		}, "10s", "2s")

	})
})

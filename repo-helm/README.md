## kube-ecr-secrets-operator:

Kubernetes Operator for managing AWS ECR (Elastic Container Registry) secrets cluster wide. ECR docker credentials expire every 12 hours, and need to be refreshed whenever you need to deploy. This operator's goal is to help manage the ECR image pull secrets by refreshing them periodically. It introduces the `AWSECRCredentials` cluster scoped object that:

1. creates a docker credential secret in all the specified namespaces upon creation
2. Once the secrets are created, the operator takes care of refreshing them periodically (every 12h)

Here is an example of the `AWSECRCredentials` specification:

```
apiVersion: aws.zakariaamine.com/v1alpha1
kind: AWSECRCredential
metadata:
  name: my-ecr-credentials
spec:
  awsAccess:
    # base64 is applied when the object is submitted (exactly like K8 secrets)
    accessKeyId: YOUR_ACCESS_KEY_ID
    secretAccessKey: YOUR_SECRET_ACCESS_KEY
    region: THE_ECR_REGION
  secretName: ecr-login
  namespaces:
    - ns1
    - ns2
    - ns3
    - ns4
```

## Installation and Usage:

The operator expects [cert-manager](https://github.com/cert-manager/cert-manager) to be present in the cluster, since it makes use of `Issuer` and `Certificate` kinds. Because there are some gotchas related to having cert-manager as a subchart(See this [issue](https://github.com/cert-manager/cert-manager/issues/3246) and this [issue](https://github.com/cert-manager/cert-manager/issues/3116) for more details ), kube-ecr-secrets-operator leaves the responsibility to the chart consumer to install it. Installation instructions can be found in the official [docs](https://cert-manager.io/docs/installation/helm/)

The operator can be installed using helm:

```
helm repo add zakariaamine https://zak905.github.io/kube-ecr-secrets-operator/repo-helm

helm repo update 

helm install --create-namespace kube-ecr-secrets-operator zakariaamine/kube-ecr-secrets-operator -n kube-ecr-secrets-operator-system

```

Once the chart is installed, `AWSECRCredentials` objects can be created.

It is, off course, highly recommended to limit the permissions of the IAM user represented by the credentials to ECR only.

## CRDs:

The `AWSECRCredentials` CRD definition is installed with the helm chart using the crds folder. However, a known shortcoming of using helm to install CRDs is the inability to update the CRDs (if there is a change) on subsequent chart upgrades. To overcome the shortcoming, one of the following solutions can help:
* The chart can be uninstalled and installed when there is a new release with a CRD change.
* The CRDs can be installed using `kubectl` as a first step `kubectl apply -f https://raw.githubusercontent.com/zak905/kube-ecr-secrets-operator/master/chart/crds/AWSECRCredentials.yaml`, and then the chart can be installed with the `--skip-crds` flag.

## Parameters:



| Name        | Description           | Value  |
| ------------- |:-------------:| -----:|
| podAnnotations      | Map of annotations to add to the operator pod | {} |
| resources.limits.cpu      | The cpu limit for the operator container      |   500m |
| resources.limits.memory      | The memory limit for the operator container      |   128Mi |
| resources.requests.cpu      | The requested cpu for the operator container       |   10m |
| resources.requests.memory      | The requested memory for the operator container       |   64Mi |
| nodeSelector | Node labels for the operator pods |    {} |
| tolerations | Tolerations for the operator pod assignment    |    {}|
| affinity | Affinity for the operator pod     |    {} |
| service.port | The port of the service exposed by the operator (used for webhooks only)      |    443 |
## kube-ecr-secrets-operator:

Kubernetes controller that helps dealing with `ImagePullBackOff` errors that may arise if a pod is rescheduled or re-started. A pod can be rescheduled or re-started any time of the day, under specific conditions (eviction, application crash,..etc). Because [AWS ECR](https://aws.amazon.com/ecr/) credentials expire every 12 hours, this may lead to disruptions due to the inability to pull the pod image, especially if the image pull policy is set to `Always`. 

kube-ecr-secrets-operator manages AWS ECR (Elastic Container Registry) secrets cluster wide. ECR docker credentials expire every 12 hours, and need to be refreshed periodically to avoid any workload disruption that may arise from a direct human action like a deploy or Kubernetes initiated action like a pod reschedule. It introduces the `ClusterAWSECRImagePullSecret` (cluster scoped) and the `AWSECRImagePullSecret` (namespaced) CRDs that:

1. creates a docker credential kubernetes secret
2. Once the secrets are created, the controller takes care of refreshing them periodically (every 12h)

Here is an example of the `AWSECRCredentials` specification:

## Examples:

```
apiVersion: aws.zakariaamine.com/v1alpha2
kind: AWSECRImagePullSecret
metadata:
  name: my-ecr-credentials
spec:
  awsAccess:
    accessKeyId: YOUR_ACCESS_KEY_ID
    secretAccessKey: YOUR_SECRET_ACCESS_KEY
    region: THE_ECR_REGION
  secretName: ecr-login
```

If the secret needs to be managed in several namespaces, the `ClusterAWSECRImagePullSecret` cluster scoped CRD can be used. It has an additional `namespaces` field under `spec` that allows specifying the namespaces.

```
apiVersion: aws.zakariaamine.com/v1alpha2
kind: ClusterAWSECRImagePullSecret
metadata:
  name: test-ecr-credentials
spec:
  awsAccess:
    accessKeyId: YOUR_ACCESS_KEY_ID
    secretAccessKey: YOUR_SECRET_ACCESS_KEY
    region: THE_ECR_REGION
  secretName: ecr-login
  namespaces:
    - ns1
    - ns2
    - ns3
```
## Installation and Usage:

The helm chart expects [cert-manager](https://github.com/cert-manager/cert-manager) to be present in the cluster, since it makes use of `Issuer` and `Certificate` kinds. Because there are some gotchas related to using cert-manager as a subchart (See this [issue](https://github.com/cert-manager/cert-manager/issues/3246) and this [issue](https://github.com/cert-manager/cert-manager/issues/3116) for more details ), kube-ecr-secrets-operator leaves the responsibility to the chart consumer to install it. Installation instructions can be found in the official [docs](https://cert-manager.io/docs/installation/helm/)

The controller can be installed using helm:

```
helm repo add zakariaamine https://zak905.github.io/kube-ecr-secrets-operator/repo-helm

helm repo update 

helm install --create-namespace kube-ecr-secrets-operator zakariaamine/kube-ecr-secrets-operator -n kube-ecr-secrets-operator-system

```

Once the chart is installed, `AWSECRImagePullSecret` and `ClusterAWSECRImagePullSecret` objects can be created.

It is, off course, highly recommended to limit the permissions of the IAM user to ECR only. Needless to say, the usage of the root AWS user credentials is highly discouraged.

## CRDs:

The CRDs definitions are part of the helm chart. A known shortcoming of using helm to install CRDs is the inability to update the CRDs (if there is a change) on subsequent chart upgrades. To overcome the shortcoming, one of the following solutions can help:
* The chart can be uninstalled and installed when there is a new release with a CRD change.
* The CRDs can be installed using `kubectl` as a first step:
  
``` 
kubectl apply -f https://raw.githubusercontent.com/zak905/kube-ecr-secrets-operator/refs/heads/master/chart/crds/aws.zakariaamine.com_awsecrcredentials.yaml
kubectl apply -f https://raw.githubusercontent.com/zak905/kube-ecr-secrets-operator/refs/heads/master/chart/crds/aws.zakariaamine.com_awsecrimagepullsecrets.yaml
kubectl apply -f https://raw.githubusercontent.com/zak905/kube-ecr-secrets-operator/refs/heads/master/chart/crds/aws.zakariaamine.com_clusterawsecrimagepullsecrets.yaml
```

and then the chart can be installed with the `--skip-crds` flag.

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
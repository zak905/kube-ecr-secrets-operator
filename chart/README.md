## Installation and Usage:

The operator expects [cert-manager](https://github.com/cert-manager/cert-manager) to be present in the cluster, since it makes use of `Issuer` and `Certificate` kinds. Because there are some gotchas related to having cert-manager as a subchart(See this [issue](https://github.com/cert-manager/cert-manager/issues/3246) and this [issue](https://github.com/cert-manager/cert-manager/issues/3116) for more details ), kube-ecr-secrets-operator leaves the responsibility to the chart consumer to install it. Installation instructions can be found in the official [docs](https://cert-manager.io/docs/installation/helm/)

The operator can be installed using helm:

```
helm repo add zakariaamine https://zak905.github.io/kube-ecr-secrets-operator/chart

helm repo update 

helm install kube-ecr-secrets-operator zakariaamine/kube-ecr-secrets-operator

```

Once the chart is installed, `AWSECRCredentials` objects can be created.

Before any `AWSECRCredentials` can be created, the secret refered to by `awsAccess` property needs to be present with following keys: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_REGION`. For example:

```
apiVersion: v1
data:
  AWS_ACCESS_KEY_ID: ACCESSKEYID
  AWS_SECRET_ACCESS_KEY: secretaccesskey
  AWS_REGION: us-east-1
kind: Secret
metadata:
  name: aws-access
```

It is, off course, highly recommended to limit the permissions of the IAM user represented by the credentials to ECR only.

Afterwards, you can create `AWSECRCredentials`. The update of the ECR credentials will be handled automatically whenver a pod is created/updated.

```
apiVersion: aws.zakariaamine.com/v1alpha1
kind: AWSECRCredential
metadata:
  name: my-ecr-credentials
spec:
  awsAccess:
    #secret containing AWS access used to get the ECR secret from AWS
    secretName: aws-access
    #optional namespace of the aws-access secret. Defaults to default.
    namespace: default
  #the name of the K8 secret that will be created
  secretName: ecr-login
  #all the namespaces in which the operator will create and manage ecr secrets
  namespaces:
    - ns1
    - ns2
    - ns3
    - ns4
```

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
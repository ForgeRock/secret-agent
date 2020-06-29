# secret-agent

Generate secrets for the Forgerock Platform

## Features

The secret-agent generates the secrets required by the ForgeRock Platform. These secretes can be stored in-cluster as Kubernetes secrets. It can also store the secrets in a Cloud Secret Manager. Currently providers supported:

* Google Secret Manager
* AWS Secrets Manager

## Usage

### Deploy

To deploy the secret-agent, run:

```bash
kustomize build config/default | kubectl apply -f -
```

## Using a cloud provider secret manager

Currently, the secret-agent supports only AWS and GCP secret managers. Azure support will be added soon.

When the operator starts, it parses the Secret Agent Configuration and queries the cloud provider's secret manager for the desired secrets. If a secret exists in the secret manager, the operator obtains the secret's value. If the secret doesn't exist, the operator moves on to it's generating phase, and will later store the secrets in the secret manager for future use. This functionality can be disabled by setting `spec.appConfig.secretsManager: none`.

### Set up AWS Secret Manager

In order to fetch and store secrets in the AWS Secrets Manager, the user must provide credentials with the necessary permissions. This library expects credentials to be discoverable via standard AWS mechanisms. These credentials can be provided in a number of ways, for example:

* Environment Variables: _AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY_
* Shared Credentials file: _~/.aws/credentials_
* Shared Configuration file: _(~/.aws/config_
* EC2 Instance Metadata: _Obtains credentials form 169.254.169.254_

Please refer to AWS documentation for instructions on how to obtain credentials and grant necessary permissions to access the AWS Secrets Manager.

Once these credentials are made available to the operator, the next step is to configure the AWS Secret Manager in the SecretAgentConfiguration.

For example, the following configuration targets AWS Secret Manager in `us-east-1`

```yaml
apiVersion: secret-agent.secrets.forgerock.io/v1alpha1
kind: SecretAgentConfiguration
metadata:
  name: standard-forgerock-example
spec:
  appConfig:
    createKubernetesObjects: true
    secretsManager: AWS
    awsRegion: us-east-1
```

### Set up GCP Secret Manager

In order to fetch and store secrets in the GCP Secrets Manager, the user must provide credentials with the necessary permissions. This library expects credentials to be discoverable via standard [GCP mechanisms](https://cloud.google.com/docs/authentication). These credentials can be provided in a number of ways, including user accounts and service accounts.

Please refer to the [GCP Documentation](https://cloud.google.com/secret-manager/docs/reference/libraries?hl=nl#cloud-console) for instructions on how to create a service account with the necessary permissions to access the GCP Secrets Manager.

Once these credentials are made available to the operator using `GOOGLE_APPLICATION_CREDENTIALS` or another mechanism, the next step is to configure the GCP Secret Manager in the `SecretAgentConfiguration`.

For example, the following configuration targets GCP Secret Manager for the `example-project-id` project.

```yaml
apiVersion: secret-agent.secrets.forgerock.io/v1alpha1
kind: SecretAgentConfiguration
metadata:
  name: standard-forgerock-example
spec:
  appConfig:
    createKubernetesObjects: true
    secretsManager: GCP
    gcpProjectID: example-project-id
```

## Running the tests

* Some of the tests exercise parts of the code that os.Exec openssl and keytool, and kubebuilder's etcd
  * It's easiest to test in Docker
  * Ensure you're kube context is hooked up to a test cluster, such as minikube, then
    * `docker build -t gcr.io/forgerock-io/secret-agent-testing:latest -f --target=tester .`
    * `docker run -it --rm -v ${PWD}:/root/go/src/github.com/ForgeRock/secret-agent gcr.io/forgerock-io/secret-agent-testing:latest`
    * `go test ./...`

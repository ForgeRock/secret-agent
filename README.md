# secret-agent

Generate secrets for the Forgerock Platform

## Features

The secret-agent generates the secrets required by the ForgeRock Platform. These secretes can be stored in-cluster as Kubernetes secrets. It can also store the secrets in a Cloud Secret Manager. Currently providers supported:

* Google Secret Manager
* AWS Secrets Manager

## Usage

### Deploy

To deploy the secret-agent with default certificates, run:

```bash
kustomize build config/default | kubectl apply -f -
```

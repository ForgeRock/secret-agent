# secret-agent

Generate secrets for the Forgerock Platform

## Features

The secret-agent generates the secrets required by the ForgeRock Platform. These secretes can be stored in-cluster as Kubernetes secrets. It can also store the secrets in a Cloud Secret Manager. Currently providers supported:

* Google Secret Manager
* AWS Secrets Manager

## Usage

### Deploy without cert-manager support (default) (#without-cert-manager)

The secret-agent implements validating webhooks. Since these webhooks must be served over HTTPS, we need proper certificates. By default, the secret-agent deployment bundles a kubernetes secret with a certificate. Although the bundled certificate is sufficient for testing environments, it is highly recommended to generate your own certificate. The certificate can be automatically generated if the secret-manager is deployed with cert-manager support. See [this section](#with-cert-manager)

To deploy the secret-agent with default certificates, run:

```bash
kustomize build config/default | kubectl apply -f -
```

### Deploy with cert-manager support (#with-cert-manager)

The secret-agent implements validating webhooks. Since these webhooks must be served over HTTPS, it is recommended to deploy the secret-agent with cert-manager support. Note you will need to have an instance of [cert-manager](https://cert-manager.io/) running in your cluster.

To deploy the secret-agent with cert-manager support, run:

```bash
kustomize build config/default-cert-manager | kubectl apply -f -
```

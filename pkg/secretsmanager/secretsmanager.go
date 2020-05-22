package secretsmanager

import (
	"context"
	"fmt"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1beta1"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/keyvault/keyvault"
	azauth "github.com/Azure/azure-sdk-for-go/services/keyvault/auth"
	"github.com/Azure/go-autorest/autorest"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	awssecretsmanager "github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/pkg/errors"
	secretspb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1beta1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
)

// LoadExisting loads any existing secrets in the secrets manager into the memory store
func LoadExisting(ctx context.Context, config *v1alpha1.SecretAgentConfigurationSpec, nodes []*v1alpha1.Node) error {
	switch config.AppConfig.SecretsManager {
	case v1alpha1.SecretsManagerGCP:
		err := loadGCPSecrets(ctx, config.AppConfig.GCPProjectID, nodes)
		if err != nil {
			return err
		}
	case v1alpha1.SecretsManagerAWS:
		err := loadAWSSecrets(config.AppConfig.AWSRegion, nodes)
		if err != nil {
			return err
		}
	case v1alpha1.SecretsManagerAzure:
		client, err := newAzureClient()
		if err != nil {
			return err
		}
		err = loadAzureSecrets(ctx, client, config.AppConfig.AzureVaultName, nodes)
		if err != nil {
			return err
		}
	}

	return nil
}

// EnsureSecrets ensures all secrets in the memory store are in the secrets manager
func EnsureSecrets(ctx context.Context, config *v1alpha1.SecretAgentConfigurationSpec, nodes []*v1alpha1.Node) error {
	switch config.AppConfig.SecretsManager {
	case v1alpha1.SecretsManagerGCP:
		err := ensureGCPSecrets(ctx, config.AppConfig.GCPProjectID, nodes)
		if err != nil {
			return err
		}
	case v1alpha1.SecretsManagerAWS:
		err := ensureAWSSecrets(config.AppConfig.AWSRegion, nodes)
		if err != nil {
			return err
		}
	}

	return nil
}

var azureVaultURLFmt string = "https://%s.vault.azure.net/"

// newAzureClient create an Azure client with an authorizer from the environment
func newAzureClient() (*keyvault.BaseClient, error) {
	authorizer, err := azauth.NewAuthorizerFromEnvironment()
	if err != nil {
		return &keyvault.BaseClient{}, err
	}
	client := keyvault.New()
	client.Authorizer = authorizer
	return &client, nil
}

// loadAzureSecrets loads any existing secrets in Azure Key Valut into the memory store
func loadAzureSecrets(ctx context.Context, client *keyvault.BaseClient, vaultName string, nodes []*v1alpha1.Node) error {
	for _, node := range nodes {
		err := loadAzureSecret(ctx, client, vaultName, node)
		if err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}

// loadAzureSecret load a secret from Azure Key Vault
func loadAzureSecret(ctx context.Context, client *keyvault.BaseClient, vaultName string, node *v1alpha1.Node) error {
	secretID := getSecretID(node.SecretConfig.Namespace, node.Path)
	response, err := client.GetSecret(ctx, fmt.Sprintf(azureVaultURLFmt, vaultName), secretID, "")
	if err != nil {
		if e, ok := err.(autorest.DetailedError); ok && e.StatusCode.(int) == 404 {
			return nil
		}
		return err
	}
	// safely dereference
	if response.Value == nil {
		return errors.WithStack(fmt.Errorf("no secret found for %s", secretID))
	}
	node.Value = []byte(*response.Value)
	return nil
}

// loadGCPSecrets loads any existing secrets in Google SecretManager into the memory store
func loadGCPSecrets(ctx context.Context, projectID string, nodes []*v1alpha1.Node) error {
	// setup client
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return errors.WithStack(err)
	}
	defer client.Close()

	// loop and load
	for _, node := range nodes {
		err := loadGCPSecret(ctx, client, projectID, node)
		if err != nil {
			return err
		}
	}

	return nil
}

// loadGCPSecret loads a single secret out of Google SecretManager, if it exists
func loadGCPSecret(ctx context.Context, client *secretmanager.Client, projectID string, node *v1alpha1.Node) error {
	secretID := getSecretID(node.SecretConfig.Namespace, node.Path)
	name := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", projectID, secretID)
	request := &secretspb.AccessSecretVersionRequest{Name: name}
	secretResponse, err := client.AccessSecretVersion(ctx, request)
	if err != nil {
		stat := status.Convert(err)
		if stat.Code() == codes.NotFound {
			// doesn't exist
			return nil
		}
		return errors.WithStack(err)
	}
	node.Value = secretResponse.GetPayload().GetData()

	return nil
}

// loadAWSSecrets loads any existing secrets in AWS SecretsManager into the memory store
func loadAWSSecrets(awsRegion string, nodes []*v1alpha1.Node) error {
	service := awssecretsmanager.New(session.New(&aws.Config{Region: aws.String(awsRegion)}))

	for _, node := range nodes {
		err := loadAWSSecret(service, node)
		if err != nil {
			return err
		}
	}

	return nil
}

// loadAWSSecret loads a single secret out of AWS SecretsManager
func loadAWSSecret(service *awssecretsmanager.SecretsManager, node *v1alpha1.Node) error {
	secretID := getSecretID(node.SecretConfig.Namespace, node.Path)
	request := &awssecretsmanager.GetSecretValueInput{SecretId: aws.String(secretID)}
	result, err := service.GetSecretValue(request)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			if aerr.Code() == awssecretsmanager.ErrCodeResourceNotFoundException {
				// doesn't exist
				return nil
			}
		}
		return errors.WithStack(err)
	}
	node.Value = []byte(*result.SecretString)

	return nil
}

// ensureGCPSecrets ensures all secrets in the memory store are in Google Secret Manager
func ensureGCPSecrets(ctx context.Context, projectID string, nodes []*v1alpha1.Node) error {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return errors.WithStack(err)
	}
	defer client.Close()

	for _, node := range nodes {
		secretID := getSecretID(node.SecretConfig.Namespace, node.Path)
		name := fmt.Sprintf("projects/%s/secrets/%s", projectID, secretID)

		// check if exists
		preExists := true
		getRequest := &secretspb.GetSecretRequest{Name: name}
		_, err := client.GetSecret(ctx, getRequest)
		if err != nil {
			stat := status.Convert(err)
			if stat.Code() != codes.NotFound {
				return errors.WithStack(err)
			}
			// doesn't exist, create
			preExists = false
			createRequest := &secretspb.CreateSecretRequest{
				Parent:   fmt.Sprintf("projects/%s", projectID),
				SecretId: secretID,
				Secret: &secretspb.Secret{
					Name: name,
					Replication: &secretspb.Replication{
						Replication: &secretspb.Replication_Automatic_{
							Automatic: &secretspb.Replication_Automatic{},
						},
					},
				},
			}
			_, err = client.CreateSecret(ctx, createRequest)
			if err != nil {
				return errors.WithStack(err)
			}
		}

		// only add new version if secret was created this round, because
		//   otherwise the in memory version was read from SM and is already correct
		if preExists {
			return nil
		}

		// add secret version
		secretVersionRequest := &secretspb.AddSecretVersionRequest{
			Parent:  name,
			Payload: &secretspb.SecretPayload{Data: node.Value},
		}
		_, err = client.AddSecretVersion(ctx, secretVersionRequest)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}

// ensureAWSSecrets ensures all secrets in the memory store are in AWS Secrets Manager
func ensureAWSSecrets(awsRegion string, nodes []*v1alpha1.Node) error {
	service := awssecretsmanager.New(session.New(&aws.Config{Region: aws.String(awsRegion)}))

	for _, node := range nodes {
		secretID := getSecretID(node.SecretConfig.Namespace, node.Path)

		// check if exists
		preExists := true
		request := &awssecretsmanager.GetSecretValueInput{SecretId: aws.String(secretID)}
		_, err := service.GetSecretValue(request)
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				if aerr.Code() != awssecretsmanager.ErrCodeResourceNotFoundException {
					return errors.WithStack(err)
				}
				// doesn't exist, create
				preExists = false
				input := &awssecretsmanager.CreateSecretInput{
					Name: aws.String(secretID),
				}
				_, err = service.CreateSecret(input)
				if err != nil {
					return errors.WithStack(err)
				}
			} else {
				return errors.WithStack(err)
			}
		}

		// only add new version if secret was created this round, because
		//   otherwise the in memory version was read from SM and is already correct
		if preExists {
			return nil
		}

		// add secret version
		valueString := string(node.Value)
		input := &awssecretsmanager.PutSecretValueInput{
			SecretId:     aws.String(secretID),
			SecretString: &valueString,
		}
		_, err = service.PutSecretValue(input)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}

func getSecretID(namespace string, path []string) string {
	secretID := ""
	switch len(path) {
	case 2:
		secretID = fmt.Sprintf("%s_%s_%s", namespace, path[0], path[1])
	case 3:
		secretID = fmt.Sprintf("%s_%s_%s_%s", namespace, path[0], path[1], path[2])
	default:
		panic("path is not of length 2 or 3!")
	}

	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(secretID, ".", "-"), "/", "-"), "_", "-")
}

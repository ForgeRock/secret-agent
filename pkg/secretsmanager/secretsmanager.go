package secretsmanager

import (
	"context"
	"fmt"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1beta1"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/keyvault/keyvault"
	azauth "github.com/Azure/azure-sdk-for-go/services/keyvault/auth"
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

func idSafe(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(value, ".", "-"), "/", "-"), "_", "-")
}

// EnsureSecret ensures a secret is stored in secret manager
func EnsureSecret(ctx context.Context, config *v1alpha1.AppConfig, secretName string, value []byte) error {
	secretID := idSafe(secretName)
	switch config.SecretsManager {
	case v1alpha1.SecretsManagerGCP:
		err := ensureGCPSecretByID(ctx, config.GCPProjectID, secretID, value)
		if err != nil {
			return err
		}
	case v1alpha1.SecretsManagerAWS:
		err := ensureAWSSecretsByID(ctx, config.AWSRegion, secretID, value)
		if err != nil {
			return err
		}

	case v1alpha1.SecretsManagerAzure:
		fmt.Print("Azure secret manager not implemented")
	}

	return nil
}

// LoadSecret Loads secrets from the configured secret manager
func LoadSecret(ctx context.Context, config *v1alpha1.AppConfig, secretName string) ([]byte, error) {
	secretID := idSafe(secretName)
	var value []byte
	var err error
	switch config.SecretsManager {
	case v1alpha1.SecretsManagerGCP:
		value, err = loadGCPSecretByID(ctx, config.GCPProjectID, secretID)
		if err != nil {
			return []byte{}, err
		}
	case v1alpha1.SecretsManagerAWS:
		value, err = loadAWSSecretByID(config.AWSRegion, secretID)
		if err != nil {
			return []byte{}, err
		}

	case v1alpha1.SecretsManagerAzure:
		fmt.Print("Azure secret manager not implemented")
	}
	return value, err

}

// GCP FUNCS

// loadGCPSecretByID loads a single secret out of Google SecretManager, if it exists
func loadGCPSecretByID(ctx context.Context, projectID string, secretID string) ([]byte, error) {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return []byte{}, err
	}
	defer client.Close()
	name := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", projectID, secretID)
	request := &secretspb.AccessSecretVersionRequest{Name: name}
	secretResponse, err := client.AccessSecretVersion(ctx, request)
	if err != nil {
		stat := status.Convert(err)
		if stat.Code() == codes.NotFound {
			// doesn't exist
			return []byte{}, nil
		}
		return []byte{}, errors.WithStack(err)
	}
	return secretResponse.GetPayload().GetData(), nil
}

// ensureGCPSecret ensures a single secret is stored in Google Secret Manager
func ensureGCPSecretByID(ctx context.Context, projectID, secretID string, value []byte) error {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	name := fmt.Sprintf("projects/%s/secrets/%s", projectID, secretID)

	// check if exists
	preExists := true
	getRequest := &secretspb.GetSecretRequest{Name: name}
	_, err = client.GetSecret(ctx, getRequest)
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
		Payload: &secretspb.SecretPayload{Data: value},
	}
	_, err = client.AddSecretVersion(ctx, secretVersionRequest)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

// AWS FUNCS

// loadAWSSecretByID loads a single secret out of AWS SecretsManager, if it exists
func loadAWSSecretByID(awsRegion string, secretID string) ([]byte, error) {
	service := awssecretsmanager.New(session.New(&aws.Config{Region: aws.String(awsRegion)}))
	request := &awssecretsmanager.GetSecretValueInput{SecretId: aws.String(secretID)}
	result, err := service.GetSecretValue(request)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			if aerr.Code() == awssecretsmanager.ErrCodeResourceNotFoundException {
				// doesn't exist
				return []byte{}, nil
			}
		}
		return []byte{}, errors.WithStack(err)
	}

	return result.SecretBinary, nil
}

// ensureAWSSecretsByID ensures a single secret is stored in AWS Secret Manager
func ensureAWSSecretsByID(ctx context.Context, awsRegion, secretID string, value []byte) error {
	service := awssecretsmanager.New(session.New(&aws.Config{Region: aws.String(awsRegion)}))

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
	input := &awssecretsmanager.PutSecretValueInput{
		SecretId:     aws.String(secretID),
		SecretBinary: value,
	}
	_, err = service.PutSecretValue(input)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

// AZURE FUNCS

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

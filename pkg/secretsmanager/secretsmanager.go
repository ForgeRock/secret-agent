package secretsmanager

import (
	"context"
	"fmt"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1beta1"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/keyvault/keyvault"
	azauth "github.com/Azure/azure-sdk-for-go/services/keyvault/auth"
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
		//Err := ensureAWSSecrets(config.AppConfig.AWSRegion, nodes)
		//If err != nil {
		//	return err
		//}
	}

	return nil
}

// LoadSecret Loads secrets from the configured secret manager
func LoadSecret(ctx context.Context, config *v1alpha1.AppConfig, secretName string) ([]byte, error) {
	secretName = idSafe(secretName)
	var value []byte
	var err error
	switch config.SecretsManager {
	case v1alpha1.SecretsManagerGCP:
		value, err = loadGCPSecretByID(ctx, config.GCPProjectID, secretName)
		if err != nil {
			return []byte{}, err
		}
	case v1alpha1.SecretsManagerAWS:
		// TODO
		//
		fmt.Print("AWS secret manager not implemented")

	case v1alpha1.SecretsManagerAzure:
		fmt.Print("AWS secret manager not implemented")
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
func ensureGCPSecretByID(ctx context.Context, projectID, secretName string, value []byte) error {
	secretID := idSafe(secretName)
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

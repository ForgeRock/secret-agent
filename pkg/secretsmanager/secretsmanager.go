package secretsmanager

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/keyvault/keyvault"
	azauth "github.com/Azure/azure-sdk-for-go/services/keyvault/auth"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aws/aws-sdk-go/aws/session"
	awssecretsmanager "github.com/aws/aws-sdk-go/service/secretsmanager"

	"github.com/pkg/errors"
	"google.golang.org/api/option"
	secretspb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/ForgeRock/secret-agent/pkg/k8ssecrets"
	log "github.com/golang/glog"
)

var (
	// 25 kb
	keyvaultMaxBytes = 25 * 1000
	// 65kb
	awssecretsManagerMaxBytes = 65 * 1000
)

func idSafe(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(value, ".", "-"), "/", "-"), "_", "-")
}

// SecretManager interface for adding or loading secret manager secrets
type SecretManager interface {
	EnsureSecret(ctx context.Context, secretName string, value []byte) error
	LoadSecret(ctx context.Context, secretName string) ([]byte, error)
	CloseClient()
}

// secretManagerGCP container for GCP secret manager properties
type secretManagerGCP struct {
	client               *secretmanager.Client
	secretsManagerPrefix string
	projectID            string
}

// secretManagerAWS container for AWS secret manager properties
type secretManagerAWS struct {
	client               *awssecretsmanager.SecretsManager
	region               string
	secretsManagerPrefix string
	cancel               context.CancelFunc
	config               v1alpha1.AppConfig
}

// secretManagerAzure container for Azure secret manager properties
type secretManagerAzure struct {
	client               *keyvault.BaseClient
	secretsManagerPrefix string
	azureVaultName       string
	cancel               context.CancelFunc
}

// secretManagerNone container for handling no secret manager
type secretManagerNone struct {
}

// NewSecretManager creates a new SecretManager object
func NewSecretManager(ctx context.Context, instance *v1alpha1.SecretAgentConfiguration, cloudCredNS string, rClient client.Client) (SecretManager, error) {

	// get namespace if not previously deployed
	config := &instance.Spec.AppConfig
	if len(cloudCredNS) == 0 {
		cloudCredNS = instance.Namespace
	}

	var sm SecretManager
	var err error

	// decide which SecretManager type based on AppConfig
	switch config.SecretsManager {
	case v1alpha1.SecretsManagerGCP:
		sm, err = newGCP(ctx, config, rClient, cloudCredNS)
		if err != nil {
			log.Error(err, "couldn't create a new GCP object")
			return nil, err
		}
	case v1alpha1.SecretsManagerAWS:
		sm, err = newAWS(config, rClient, cloudCredNS)
	case v1alpha1.SecretsManagerAzure:
		sm, err = newAzure(config, rClient, cloudCredNS)
	case v1alpha1.SecretsManagerNone:
		sm = newNone() // if secretmanager in the config is "none" then return this
	}

	return sm, err
}

// newGCP configures a GCP secret manager object
func newGCP(ctx context.Context, config *v1alpha1.AppConfig, rClient client.Client, cloudCredNS string) (*secretManagerGCP, error) {

	var client *secretmanager.Client
	var clientErr error

	// if credentials secret is provided
	if config.CredentialsSecretName != "" {
		// load credentials secret from Kubernetes secret
		secObject, err := LoadCredentialsSecret(rClient, config, cloudCredNS)
		if err != nil {
			return &secretManagerGCP{}, err
		}

		// Create temporary dir for gcp credentials if needed
		dir, err := ioutil.TempDir("", "cloud_credentials-*")
		if err != nil {
			log.Error(err, "couldn't create a temporary credentials dir")
			return &secretManagerGCP{}, err
		}

		// clean up after ourselves
		defer os.RemoveAll(dir)

		// open a new file for writing
		writeFile := func(name string, contents []byte) (string, error) {
			fPath := path.Join(dir, name)

			// open a new file for writing only
			file, err := os.OpenFile(
				fPath,
				os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
				0666,
			)
			if err != nil {
				return "", err
			}

			// close file when finished
			defer file.Close()

			// write bytes to file
			_, err = file.Write(contents)
			if err != nil {
				return "", err
			}
			return fPath, nil
		}

		// get credential data
		keyValue, err := getCredentialData(secObject)
		if err != nil {
			return &secretManagerGCP{}, err
		}

		// write credential data to file
		fp, err := writeFile("gcp_credentials.json", keyValue)
		if err != nil {
			log.Error(err, "couldn't write credential data to file")
			return &secretManagerGCP{}, err
		}

		// Create client with credentials file
		client, clientErr = secretmanager.NewClient(ctx, option.WithCredentialsFile(fp))
	} else {
		// Create client without credentials file
		client, clientErr = secretmanager.NewClient(ctx)
	}

	if clientErr != nil {
		log.Error(clientErr, "couldn't create Google Secret Manager client")
		return &secretManagerGCP{}, clientErr
	}

	return &secretManagerGCP{
		client:               client,
		secretsManagerPrefix: config.SecretsManagerPrefix,
		projectID:            config.GCPProjectID,
	}, nil
}

// newAWS configures a AWS secret manager object
func newAWS(config *v1alpha1.AppConfig, rClient client.Client, cloudCredNS string) (*secretManagerAWS, error) {
	var accessKey string
	var secretAccessKey string
	var client *awssecretsmanager.SecretsManager

	// if credentials secret is provided
	if config.CredentialsSecretName != "" {
		// load credentials secret from Kubernetes secret
		secObject, err := LoadCredentialsSecret(rClient, config, cloudCredNS)
		if err != nil {
			return &secretManagerAWS{}, err
		}

		// extract access AWS_ACCESS_KEY_ID from Kubernetes secret
		if keyValue, ok := secObject.Data[string(v1alpha1.SecretsManagerAwsAccessKeyID)]; ok {
			accessKey = string(keyValue)
		} else {
			return &secretManagerAWS{}, fmt.Errorf(fmt.Sprintf("Can't read %s. Cloud credentials secret must contain a access key ID", v1alpha1.SecretsManagerAwsAccessKeyID))
		}

		// extract AWS_SECRET_ACCESS_KEY from Kubernetes secret
		if keyValue, ok := secObject.Data[string(v1alpha1.SecretsManagerAwsSecretAccessKey)]; ok {
			secretAccessKey = string(keyValue)
		} else {
			return &secretManagerAWS{}, fmt.Errorf(fmt.Sprintf("Can't read %s. Cloud credentials secret must contain a secret access key", v1alpha1.SecretsManagerAwsSecretAccessKey))
		}

		// create secrets manager client
		client = awssecretsmanager.New(session.New(&aws.Config{
			Region:      aws.String(config.AWSRegion),
			Credentials: credentials.NewStaticCredentials(accessKey, secretAccessKey, ""),
		}))
	} else {
		// create secrets manager client
		client = awssecretsmanager.New(session.New(&aws.Config{
			Region: aws.String(config.AWSRegion),
		}))
	}

	// secretCtx, cancel := context.WithTimeout(ctx, 40*time.Second)

	return &secretManagerAWS{
		client:               client,
		secretsManagerPrefix: config.SecretsManagerPrefix,
		region:               config.AWSRegion,
		config:               *config,
		// cancel: cancel,
	}, nil
}

// newAzure configures a Azure secret manager object
func newAzure(config *v1alpha1.AppConfig, rClient client.Client, cloudCredNS string) (*secretManagerAzure, error) {

	var authErr error
	var authorizer autorest.Authorizer

	// if credentials secret is provided
	if config.CredentialsSecretName != "" {
		var tenantID string
		var clientID string
		var clientSecret string

		// load credentials secret from Kubernetes secret
		secObject, err := LoadCredentialsSecret(rClient, config, cloudCredNS)
		if err != nil {
			return &secretManagerAzure{}, err
		}
		// extract AZURE_TENANT_ID from Kubernetes secret
		if keyValue, ok := secObject.Data[string(v1alpha1.SecretsManagerAzureTenantID)]; ok {
			tenantID = string(keyValue)
		} else {
			return &secretManagerAzure{}, fmt.Errorf(fmt.Sprintf("Can't read %s. Cloud credentials secret must contain a valid tenant ID", v1alpha1.SecretsManagerAzureTenantID))
		}

		// extract AZURE_CLIENT_ID from Kubernetes secret
		if keyValue, ok := secObject.Data[string(v1alpha1.SecretsManagerAzureClientID)]; ok {
			clientID = string(keyValue)
		} else {
			return &secretManagerAzure{}, fmt.Errorf(fmt.Sprintf("Can't read %s. Cloud credentials secret must contain a valid client ID", v1alpha1.SecretsManagerAzureClientID))
		}

		// extract AZURE_CLIENT_SECRET from Kubernetes secret
		if keyValue, ok := secObject.Data[string(v1alpha1.SecretsManagerAzureClientSecret)]; ok {
			clientSecret = string(keyValue)
		} else {
			return &secretManagerAzure{}, fmt.Errorf(fmt.Sprintf("Can't read %s. Cloud credentials secret must contain a valid client secret", v1alpha1.SecretsManagerAzureClientSecret))
		}

		// Create am authorizer with supplied credentials
		credentialsAuthorizer := auth.NewClientCredentialsConfig(clientID, clientSecret, tenantID)
		credentialsAuthorizer.Resource = azure.PublicCloud.ResourceIdentifiers.KeyVault
		authorizer, authErr = credentialsAuthorizer.Authorizer()
	} else {
		// set default authorizer
		authorizer, authErr = azauth.NewAuthorizerFromEnvironment()
	}

	// create Keyvault client
	client := keyvault.New()
	client.Authorizer = authorizer

	// secretCtx, cancel := context.WithTimeout(ctx, 40*time.Second)

	return &secretManagerAzure{
		client:               &client,
		secretsManagerPrefix: config.SecretsManagerPrefix,
		azureVaultName:       config.AzureVaultName,
	}, authErr
}

// newNone configures an empty secret manager object
func newNone() *secretManagerNone {
	return &secretManagerNone{}
}

// getSecretID returns a secretID
func getSecretID(prefix string, secretName string) string {
	secretID := idSafe(secretName)
	if prefix != "" {
		secretID = fmt.Sprintf("%s-%s", prefix, secretID)
	}
	return secretID
}

// GCP FUNCS

// CloseClient closes GCP client
func (sm *secretManagerGCP) CloseClient() {
	if err := sm.client.Close(); err != nil {
		log.Error(err, "Problem closing client")
	}
}

// EnsureSecret ensures a single secret is stored in Google Secret Manager
func (sm *secretManagerGCP) EnsureSecret(ctx context.Context, secretName string, value []byte) error {
	// get secret ID
	secretID := getSecretID(sm.secretsManagerPrefix, secretName)

	name := fmt.Sprintf("projects/%s/secrets/%s", sm.projectID, secretID)

	// check if exists
	preExists := true
	getRequest := &secretspb.GetSecretRequest{Name: name}
	_, err := sm.client.GetSecret(ctx, getRequest)

	if err != nil {
		stat := status.Convert(err)
		if stat.Code() != codes.NotFound {
			return errors.WithStack(err)
		}
		// doesn't exist, create
		preExists = false
		createRequest := &secretspb.CreateSecretRequest{
			Parent:   fmt.Sprintf("projects/%s", sm.projectID),
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
		_, err = sm.client.CreateSecret(ctx, createRequest)
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
	_, err = sm.client.AddSecretVersion(ctx, secretVersionRequest)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

// LoadSecret loads a single secret out of Google SecretManager, if it exists
func (sm *secretManagerGCP) LoadSecret(ctx context.Context, secretName string) ([]byte, error) {
	// get secret ID
	secretID := getSecretID(sm.secretsManagerPrefix, secretName)

	name := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", sm.projectID, secretID)
	request := &secretspb.AccessSecretVersionRequest{Name: name}
	secretResponse, err := sm.client.AccessSecretVersion(ctx, request)

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

// AWS FUNCS

// CloseClient empty function to fulfil interface functions
func (sm *secretManagerAWS) CloseClient() {}

// EnsureSecret saves secret to AWS secret manager
func (sm *secretManagerAWS) EnsureSecret(ctx context.Context, secretName string, value []byte) error {
	// get secret ID
	if binary.Size(value) > awssecretsManagerMaxBytes {
		return errors.WithStack(fmt.Errorf("unable to write %s to AWS secret manager size exceeds 65kb", secretName))
	}
	secretID := getSecretID(sm.secretsManagerPrefix, secretName)

	// check if exists
	preExists := true
	request := &awssecretsmanager.GetSecretValueInput{SecretId: aws.String(secretID)}
	_, err := sm.client.GetSecretValue(request)
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
			if sm.config.AWSKmsKeyId != "" {
				input.KmsKeyId = aws.String(sm.config.AWSKmsKeyId)
			}
			_, err = sm.client.CreateSecret(input)
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
	_, err = sm.client.PutSecretValue(input)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

// LoadSecret loads a single secret out of AWS SecretsManager, if it exists
func (sm *secretManagerAWS) LoadSecret(ctx context.Context, secretName string) ([]byte, error) {
	// get secret ID
	secretID := getSecretID(sm.secretsManagerPrefix, secretName)

	request := &awssecretsmanager.GetSecretValueInput{SecretId: aws.String(secretID)}
	result, err := sm.client.GetSecretValue(request)
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

// AZURE FUNCS

// CloseClient empty function to fulfil interface functions
func (sm *secretManagerAzure) CloseClient() {}

var azureVaultURLFmt string = "https://%s.vault.azure.net/"

// EnsureSecret ensures a single secret is stored in AWS Secret Manager
func (sm *secretManagerAzure) EnsureSecret(ctx context.Context, secretName string, value []byte) error {
	// get secret ID
	secretID := getSecretID(sm.secretsManagerPrefix, secretName)

	var secParams keyvault.SecretSetParameters
	stringValue := base64.StdEncoding.EncodeToString(value)
	if binary.Size(stringValue) > keyvaultMaxBytes {
		return errors.WithStack(fmt.Errorf("unable to write %s to azure vault secret exceeds 25kb", secretID))
	}
	secParams.Value = &stringValue
	_, err := sm.client.SetSecret(ctx, fmt.Sprintf(azureVaultURLFmt, sm.azureVaultName), secretID, secParams)
	if err != nil {
		return errors.WithStack(fmt.Errorf("unable to write %s to azure vault", secretID))
	}
	return nil
}

// LoadSecret loads a secret from Azure Key Vault
func (sm *secretManagerAzure) LoadSecret(ctx context.Context, secretName string) ([]byte, error) {
	// get secret ID
	secretID := getSecretID(sm.secretsManagerPrefix, secretName)

	response, err := sm.client.GetSecret(ctx, fmt.Sprintf(azureVaultURLFmt, sm.azureVaultName), secretID, "")
	if err != nil {
		// We can ignore some errors
		if de, ok := err.(autorest.DetailedError); ok {
			if re, ok := de.Original.(*azure.RequestError); ok {
				if re.ServiceError.Code == "SecretNotFound" {
					// Secret not existing is fine, as that means we will create a new secret
					return []byte{}, nil
				} else if code, ok := re.ServiceError.InnerError["code"].(string); ok && code == "SecretDisabled" {
					// Disabled secret also fine, as it means we will create a new version of the secret
					return []byte{}, nil
				}
			}
		}
		return []byte{}, err
	}
	// safely dereference
	if response.Value == nil {
		return []byte{}, errors.WithStack(fmt.Errorf("no secret found for %s", secretID))
	}
	value, err := base64.StdEncoding.DecodeString(*response.Value)
	return []byte(value), err
}

// No Secret Manager Client
func (sm *secretManagerNone) CloseClient() {}

// EnsureSecret returns nil if SecretsManagerNone is true
func (sm *secretManagerNone) EnsureSecret(ctx context.Context, secretName string, value []byte) error {
	return nil
}

// LoadSecret returns nil if SecretsManagerNone is true
func (sm *secretManagerNone) LoadSecret(ctx context.Context, secretName string) ([]byte, error) {
	return nil, nil
}

// LoadCredentialsSecret loads the credential secret data from the Kubernetes secret
func LoadCredentialsSecret(rClient client.Client, config *v1alpha1.AppConfig, cloudCredNS string) (*corev1.Secret, error) {
	// load credentials secret
	secObject, err := k8ssecrets.LoadSecret(rClient, config.CredentialsSecretName, cloudCredNS)
	if err != nil {
		log.Error(err, "error loading cloud credentials secret from the Kubernetes API",
			"secret_name", config.CredentialsSecretName,
			"cloud_secret_namespace", cloudCredNS)
	}
	return secObject, err
}

// getCredentialData extracts the credential data from the data field
func getCredentialData(secObject *corev1.Secret) ([]byte, error) {
	// get credential data
	keyValue, ok := secObject.Data[string(v1alpha1.SecretsManagerGoogleApplicationCredentials)]
	if !ok {
		return keyValue, fmt.Errorf(fmt.Sprintf("%s must be provided in a credentials secret",
			v1alpha1.SecretsManagerGoogleApplicationCredentials))
	}
	return keyValue, nil
}

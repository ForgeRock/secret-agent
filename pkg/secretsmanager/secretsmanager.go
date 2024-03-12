package secretsmanager

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretspb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/ForgeRock/secret-agent/pkg/k8ssecrets"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awssecretsmanager "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/go-logr/logr"
	"github.com/googleapis/gax-go/v2"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

type secretsGcpApi interface {
	GetSecret(ctx context.Context, req *secretspb.GetSecretRequest, opts ...gax.CallOption) (*secretspb.Secret, error)
	CreateSecret(ctx context.Context, req *secretspb.CreateSecretRequest, opts ...gax.CallOption) (*secretspb.Secret, error)
	AccessSecretVersion(ctx context.Context, req *secretspb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretspb.AccessSecretVersionResponse, error)
	AddSecretVersion(ctx context.Context, req *secretspb.AddSecretVersionRequest, opts ...gax.CallOption) (*secretspb.SecretVersion, error)
	Close() error
}

// secretManagerGCP container for GCP secret manager properties
type secretManagerGCP struct {
	client               secretsGcpApi
	secretsManagerPrefix string
	projectID            string
	log                  logr.Logger
}

type secretsMgrApi interface {
	GetSecretValue(ctx context.Context, params *awssecretsmanager.GetSecretValueInput, optFns ...func(*awssecretsmanager.Options)) (*awssecretsmanager.GetSecretValueOutput, error)
	CreateSecret(ctx context.Context, params *awssecretsmanager.CreateSecretInput, optFns ...func(*awssecretsmanager.Options)) (*awssecretsmanager.CreateSecretOutput, error)
	PutSecretValue(ctx context.Context, params *awssecretsmanager.PutSecretValueInput, optFns ...func(*awssecretsmanager.Options)) (*awssecretsmanager.PutSecretValueOutput, error)
}

// secretManagerAWS container for AWS secret manager properties
type secretManagerAWS struct {
	client               secretsMgrApi
	region               string
	secretsManagerPrefix string
	cancel               context.CancelFunc
	config               v1alpha1.AppConfig
	log                  logr.Logger
}

type azKvApi interface {
	GetSecret(ctx context.Context, name string, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error)
	SetSecret(ctx context.Context, name string, parameters azsecrets.SetSecretParameters, options *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error)
}

// secretManagerAzure container for Azure secret manager properties
type secretManagerAzure struct {
	client               azKvApi
	secretsManagerPrefix string
	cancel               context.CancelFunc
	log                  logr.Logger
}

// secretManagerNone container for handling no secret manager
type secretManagerNone struct {
}

// NewSecretManager creates a new SecretManager object
func NewSecretManager(ctx context.Context, instance *v1alpha1.SecretAgentConfiguration, cloudCredNS string, rClient client.Client, log logr.Logger) (SecretManager, error) {

	// get namespace if not previously deployed
	config := &instance.Spec.AppConfig
	if len(cloudCredNS) == 0 {
		cloudCredNS = instance.Namespace
	}

	log.WithName("SecretManager")

	var sm SecretManager
	var err error

	// decide which SecretManager type based on AppConfig
	switch config.SecretsManager {
	case v1alpha1.SecretsManagerGCP:
		sm, err = newGCP(ctx, config, rClient, cloudCredNS, log)
		if err != nil {
			log.Error(err, "couldn't create a new GCP object")
			return nil, err
		}
	case v1alpha1.SecretsManagerAWS:
		sm, err = newAWS(ctx, config, rClient, cloudCredNS, log)
	case v1alpha1.SecretsManagerAzure:
		sm, err = newAzure(config, rClient, cloudCredNS, log)
	case v1alpha1.SecretsManagerNone:
		sm = newNone() // if secretmanager in the config is "none" then return this
	}

	return sm, err
}

// newGCP configures a GCP secret manager object
func newGCP(ctx context.Context, config *v1alpha1.AppConfig, rClient client.Client, cloudCredNS string, log logr.Logger) (*secretManagerGCP, error) {

	log.WithName("GCPSecrets")
	// if credentials secret is provided
	if config.CredentialsSecretName != "" {
		// load credentials secret from Kubernetes secret
		secObject, err := LoadCredentialsSecret(rClient, config, cloudCredNS, log)
		if err != nil {
			return &secretManagerGCP{}, err
		}

		// Create temporary dir for gcp credentials if needed
		credsFile, err := os.CreateTemp("", "cloud_credentials-*")
		if err != nil {
			log.Error(err, "couldn't create a temporary credentials dir")
			return &secretManagerGCP{}, err
		}
		// Once creds are loaded from the file it can be deleted
		// NOTE: it might be better to save it to a known location
		// One that isn't a mounted path - this would potentially save on the I/O
		// clean up after ourselves
		defer os.Remove(credsFile.Name())

		if err := credsFile.Chmod(0666); err != nil {
			return &secretManagerGCP{}, err
		}

		// get credential data
		keyValue, err := getCredentialData(secObject)
		if err != nil {
			return &secretManagerGCP{}, err
		}

		if _, err := credsFile.Write(keyValue); err != nil {
			return &secretManagerGCP{}, err
		}
		// Should set GOOGLE_APPLICATION_CREDENTIALS env var if all successfully written out
		// once the NewClient defaults are run through and this environment variable is present
		// it will load credentials from this location
		os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credsFile.Name())
	}

	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return &secretManagerGCP{}, err
	}

	return &secretManagerGCP{
		client:               client,
		secretsManagerPrefix: config.SecretsManagerPrefix,
		projectID:            config.GCPProjectID,
		log:                  log,
	}, nil
}

// newAWS configures a AWS secret manager object
func newAWS(ctx context.Context, config *v1alpha1.AppConfig, rClient client.Client, cloudCredNS string, log logr.Logger) (*secretManagerAWS, error) {

	log.WithName("AWSSecretsManager")

	// if credentials are provided via a Kubernetes secret
	//
	// This should be considered a legacy method
	//
	// Prefer to use service account on the deployment _WHEN_ running in AWS
	// hence the AWS_WEB_ID_TOKEN_FILE method provided in the chain
	if config.CredentialsSecretName != "" {
		// load credentials secret from Kubernetes secret
		secObject, err := LoadCredentialsSecret(rClient, config, cloudCredNS, log)
		if err != nil {
			return &secretManagerAWS{}, err
		}

		// extract access AWS_ACCESS_KEY_ID from Kubernetes secret
		if keyValue, ok := secObject.Data[string(v1alpha1.SecretsManagerAwsAccessKeyID)]; ok {
			os.Setenv("AWS_ACCESS_KEY_ID", string(keyValue))
		} else {
			return &secretManagerAWS{}, fmt.Errorf(fmt.Sprintf("Can't read %s. Cloud credentials secret must contain a access key ID", v1alpha1.SecretsManagerAwsAccessKeyID))
		}

		// extract AWS_SECRET_ACCESS_KEY from Kubernetes secret
		if keyValue, ok := secObject.Data[string(v1alpha1.SecretsManagerAwsSecretAccessKey)]; ok {
			// statically add AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
			// so that the default credentials will automatically take them
			// as this is in process os.SetEnv it will not be leaked to the parent process
			//
			os.Setenv("AWS_SECRET_ACCESS_KEY", string(keyValue))
		} else {
			return &secretManagerAWS{}, fmt.Errorf(fmt.Sprintf("Can't read %s. Cloud credentials secret must contain a secret access key", v1alpha1.SecretsManagerAwsSecretAccessKey))
		}
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		log.Error(err, "unable to load SDK config")
		return nil, err
	}

	return &secretManagerAWS{
		client:               awssecretsmanager.NewFromConfig(cfg),
		secretsManagerPrefix: config.SecretsManagerPrefix,
		region:               config.AWSRegion,
		config:               *config,
		log:                  log,
		// cancel:               cancel,
	}, nil
}

// azureVaultURLFmt used to initialise the client
// v1alpha1.AppConfig.AzureVaultName will contain the vault name
var azureVaultURLFmt string = "https://%s.vault.azure.net/"

// newAzure configures a Azure secret manager object
func newAzure(config *v1alpha1.AppConfig, rClient client.Client, cloudCredNS string, log logr.Logger) (*secretManagerAzure, error) {
	log.WithName("AzureKeyVault")
	// if credentials secret is provided
	//
	if config.CredentialsSecretName != "" {
		// load credentials secret from Kubernetes secret
		secObject, err := LoadCredentialsSecret(rClient, config, cloudCredNS, log)
		if err != nil {
			return &secretManagerAzure{}, err
		}
		// extract AZURE_TENANT_ID from Kubernetes secret
		if keyValue, ok := secObject.Data[string(v1alpha1.SecretsManagerAzureTenantID)]; ok {
			os.Setenv("AZURE_TENANT_ID", string(keyValue))
		} else {
			return &secretManagerAzure{}, fmt.Errorf(fmt.Sprintf("Can't read %s. Cloud credentials secret must contain a valid tenant ID", v1alpha1.SecretsManagerAzureTenantID))
		}

		// extract AZURE_CLIENT_ID from Kubernetes secret
		if keyValue, ok := secObject.Data[string(v1alpha1.SecretsManagerAzureClientID)]; ok {
			os.Setenv("AZURE_CLIENT_ID", string(keyValue))
		} else {
			return &secretManagerAzure{}, fmt.Errorf(fmt.Sprintf("Can't read %s. Cloud credentials secret must contain a valid client ID", v1alpha1.SecretsManagerAzureClientID))
		}

		// extract AZURE_CLIENT_SECRET from Kubernetes secret
		if keyValue, ok := secObject.Data[string(v1alpha1.SecretsManagerAzureClientSecret)]; ok {
			// statically add
			// so that the default credentials will automatically take them
			// as this is in process os.SetEnv it will not be leaked to the parent process
			// [reference](https://learn.microsoft.com/en-us/azure/developer/go/azure-sdk-authentication?tabs=bash#-option-1-define-environment-variables)
			os.Setenv("AZURE_CLIENT_SECRET", string(keyValue))
		} else {
			return &secretManagerAzure{}, fmt.Errorf(fmt.Sprintf("Can't read %s. Cloud credentials secret must contain a valid client secret", v1alpha1.SecretsManagerAzureClientSecret))
		}

	}

	// When running in AKs the prefered
	// [method is #2](https://learn.microsoft.com/en-us/azure/developer/go/azure-sdk-authentication?tabs=bash#-option-2-use-workload-identity)
	// else injected EnvVariables will be used
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, err
	}

	client, err := azsecrets.NewClient(fmt.Sprintf(azureVaultURLFmt, config.AzureVaultName), cred, nil)
	if err != nil {
		return nil, err
	}

	return &secretManagerAzure{
		client:               client,
		secretsManagerPrefix: config.SecretsManagerPrefix,
		log:                  log,
	}, nil
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
		sm.log.Error(err, "Problem closing GCP client")
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
	// otherwise the in memory version was read from SM and is already correct
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
	_, err := sm.client.GetSecretValue(ctx, request)
	if err != nil {
		var nf *types.ResourceNotFoundException
		if errors.As(err, &nf) {
			// doesn't exist, create
			preExists = false
			input := &awssecretsmanager.CreateSecretInput{
				Name: aws.String(secretID),
			}
			if sm.config.AWSKmsKeyId != "" {
				input.KmsKeyId = aws.String(sm.config.AWSKmsKeyId)
			}
			if _, err := sm.client.CreateSecret(ctx, input); err != nil {
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
	if _, err := sm.client.PutSecretValue(ctx, input); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// LoadSecret loads a single secret out of AWS SecretsManager, if it exists
func (sm *secretManagerAWS) LoadSecret(ctx context.Context, secretName string) ([]byte, error) {
	// get secret ID
	secretID := getSecretID(sm.secretsManagerPrefix, secretName)

	request := &awssecretsmanager.GetSecretValueInput{SecretId: aws.String(secretID)}
	result, err := sm.client.GetSecretValue(ctx, request)
	if err != nil {
		var nf *types.ResourceNotFoundException
		if errors.As(err, &nf) {
			return []byte{}, nil
		}
		return []byte{}, errors.WithStack(err)
	}
	return result.SecretBinary, nil
}

// AZURE FUNCS

// CloseClient empty function to fulfil interface functions
func (sm *secretManagerAzure) CloseClient() {}

// EnsureSecret ensures a single secret is stored in AWS Secret Manager
func (sm *secretManagerAzure) EnsureSecret(ctx context.Context, secretName string, value []byte) error {
	// get secret ID
	secretID := getSecretID(sm.secretsManagerPrefix, secretName)

	stringValue := base64.StdEncoding.EncodeToString(value)
	if binary.Size(stringValue) > keyvaultMaxBytes {
		return errors.WithStack(fmt.Errorf("unable to write %s to azure vault secret exceeds 25kb", secretID))
	}
	secParams := azsecrets.SetSecretParameters{
		Value: &stringValue,
	}
	_, err := sm.client.SetSecret(ctx, secretID, secParams, nil)
	if err != nil {
		return errors.WithStack(fmt.Errorf("unable to write %s to azure vault", secretID))
	}
	return nil
}

// LoadSecret loads a secret from Azure Key Vault
func (sm *secretManagerAzure) LoadSecret(ctx context.Context, secretName string) ([]byte, error) {
	// get secret ID
	secretID := getSecretID(sm.secretsManagerPrefix, secretName)

	response, err := sm.client.GetSecret(ctx, secretID, "", nil)
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
	if response.Value != nil {
		value, err := base64.StdEncoding.DecodeString(*response.Value)
		return []byte(value), err
	}
	return []byte{}, errors.WithStack(fmt.Errorf("no secret found for %s", secretID))
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
func LoadCredentialsSecret(rClient client.Client, config *v1alpha1.AppConfig, cloudCredNS string, log logr.Logger) (*corev1.Secret, error) {
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

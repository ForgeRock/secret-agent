package secretsmanager

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"strings"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1beta1"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/keyvault/keyvault"
	azauth "github.com/Azure/azure-sdk-for-go/services/keyvault/auth"
	"github.com/Azure/go-autorest/autorest"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/prometheus/common/log"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aws/aws-sdk-go/aws/session"
	awssecretsmanager "github.com/aws/aws-sdk-go/service/secretsmanager"

	"github.com/pkg/errors"
	secretspb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1beta1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/ForgeRock/secret-agent/pkg/k8ssecrets"
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

//  secretManagerGCP container for GCP secret manager properties
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
func NewSecretManager(ctx context.Context, instance *v1alpha1.SecretAgentConfiguration, cloudCredNS string, rClient client.Client) (context.Context, SecretManager, error) {

	config := &instance.Spec.AppConfig
	if len(cloudCredNS) == 0 {
		cloudCredNS = instance.Namespace
	}

	if instance.Spec.AppConfig.CredentialsSecretName != "" {
		// load credentials secret
		secObject, err := k8ssecrets.LoadSecret(rClient,
			config.CredentialsSecretName, cloudCredNS)
		if err != nil {
			log.Error(err, "error loading cloud credentials secret from the Kubernetes API",
				"secret_name", config.CredentialsSecretName,
				"cloud_secret_namespace", cloudCredNS)
			return ctx, nil, err
		}

		var dir string

		if err := manageCloudCredentials(config.SecretsManager, secObject, dir); err != nil {
			log.Error(err, "error loading cloud credentials from secret provided",
				"secret_name", config.CredentialsSecretName,
				"cloud_secret_namespace", cloudCredNS)
		}
	}

	var sm SecretManager
	var err error

	// decide which SecretManager type based on AppConfig
	switch config.SecretsManager {
	case v1alpha1.SecretsManagerGCP:
		sm, err = newGCP(ctx, config)
		if err != nil {
			log.Error(err, "couldn't create a new GCP object")
			return ctx, nil, err
		}
		dir, err := ioutil.TempDir("", "cloud_credentials-*")
		println(dir)
		if err != nil {
			log.Error(err, "couldn't create a temporary credentials dir")
			return ctx, nil, err
		}
		// clean up after ourselves
		defer os.RemoveAll(dir)
	case v1alpha1.SecretsManagerAWS:
		ctx, sm = newAWS(ctx, config)
	case v1alpha1.SecretsManagerAzure:
		ctx, sm, err = newAzure(ctx, config)
	case v1alpha1.SecretsManagerNone:
		sm = newNone() // if secretmanager in the config is "none" then return this
	}

	return ctx, sm, err
}

// newGCP configures a GCP secret manager object
func newGCP(ctx context.Context, conf *v1alpha1.AppConfig) (*secretManagerGCP, error) {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		log.Error(err, "couldn't create Google Secret Manager client")
		return &secretManagerGCP{}, err
	}

	return &secretManagerGCP{
		client:               client,
		secretsManagerPrefix: conf.SecretsManagerPrefix,
		projectID:            conf.GCPProjectID,
	}, err
}

// newAWS configures a AWS secret manager object
func newAWS(ctx context.Context, conf *v1alpha1.AppConfig) (context.Context, *secretManagerAWS) {
	client := awssecretsmanager.New(session.New(&aws.Config{Region: aws.String(conf.AWSRegion)}))
	secretCtx, cancel := context.WithTimeout(ctx, 40*time.Second)

	return secretCtx, &secretManagerAWS{
		client: client,
		region: conf.AWSRegion,
		cancel: cancel,
	}
}

// newAzure configures a Azure secret manager object
func newAzure(ctx context.Context, conf *v1alpha1.AppConfig) (context.Context, *secretManagerAzure, error) {
	client, err := newAzureClient()
	secretCtx, cancel := context.WithTimeout(ctx, 40*time.Second)

	return secretCtx, &secretManagerAzure{
		client:               client,
		secretsManagerPrefix: conf.SecretsManagerPrefix,
		azureVaultName:       conf.AzureVaultName,
		cancel:               cancel,
	}, err
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

// CloseClient closes AWS client
func (sm *secretManagerAWS) CloseClient() {
	sm.cancel()
}

// EnsureSecret saves secret to AWS secret manager
func (sm *secretManagerAWS) EnsureSecret(ctx context.Context, secretName string, value []byte) error {
	// get secret ID
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

// CloseClient closes Azure client
func (sm *secretManagerAzure) CloseClient() {
	sm.cancel()
}

var azureVaultURLFmt string = "https://%s.vault.azure.net/"

// newAzureClient create an Azure client with an authorizer from the environment
func newAzureClient() (*keyvault.BaseClient, error) {
	authorizer, err := azauth.NewAuthorizerFromEnvironment()
	if err != nil {
		return &keyvault.BaseClient{}, err
	}
	// authorizer
	client := keyvault.New()
	client.Authorizer = authorizer
	return &client, nil
}

// EnsureSecret ensures a single secret is stored in AWS Secret Manager
func (sm *secretManagerAzure) EnsureSecret(ctx context.Context, secretName string, value []byte) error {
	// get secret ID
	secretID := getSecretID(sm.secretsManagerPrefix, secretName)

	var secParams keyvault.SecretSetParameters
	stringValue := string(value)
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
		if e, ok := err.(autorest.DetailedError); ok && e.StatusCode.(int) == 404 {
			return []byte{}, nil
		}
		return []byte{}, err
	}
	// safely dereference
	if response.Value == nil {
		return []byte{}, errors.WithStack(fmt.Errorf("no secret found for %s", secretID))
	}
	return []byte(*response.Value), nil
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

// manageCloudCredentials handles the credential used to access the secret manager
// credentials are placed in temp files or environmental variables according to the SM specs.
func manageCloudCredentials(secMan v1alpha1.SecretsManager, secObject *corev1.Secret, dirPath string) error {

	writeFile := func(name string, contents []byte) (string, error) {
		fPath := path.Join(dirPath, name)

		// Open a new file for writing only
		file, err := os.OpenFile(
			fPath,
			os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
			0666,
		)
		if err != nil {
			return "", err
		}
		defer file.Close()

		// Write bytes to file
		_, err = file.Write(contents)
		if err != nil {
			return "", err
		}
		return fPath, nil
	}
	switch secMan {
	case v1alpha1.SecretsManagerGCP:
		keyValue, ok := secObject.Data[string(v1alpha1.SecretsManagerGoogleApplicationCredentials)]
		if !ok {
			return fmt.Errorf(fmt.Sprintf("%s must be provided in a credentials secret",
				v1alpha1.SecretsManagerGoogleApplicationCredentials))
		}
		fp, err := writeFile("gcp_credentials.json", keyValue)
		if err != nil {
			return err
		}
		if err := os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", fp); err != nil {
			return err
		}
	case v1alpha1.SecretsManagerAWS:
		if keyValue, ok := secObject.Data[string(v1alpha1.SecretsManagerAwsAccessKeyID)]; ok {
			if err := os.Setenv("AWS_ACCESS_KEY_ID", string(keyValue)); err != nil {
				return err
			}
		}
		if keyValue, ok := secObject.Data[string(v1alpha1.SecretsManagerAwsSecretAccessKey)]; ok {
			if err := os.Setenv("AWS_SECRET_ACCESS_KEY", string(keyValue)); err != nil {
				return err
			}
		}
	case v1alpha1.SecretsManagerAzure:
		if keyValue, ok := secObject.Data[string(v1alpha1.SecretsManagerAzureTenantID)]; ok {
			if err := os.Setenv("AZURE_TENANT_ID", string(keyValue)); err != nil {
				return err
			}

		}
		if keyValue, ok := secObject.Data[string(v1alpha1.SecretsManagerAzureClientID)]; ok {
			if err := os.Setenv("AZURE_CLIENT_ID", string(keyValue)); err != nil {
				return err
			}

		}
		if keyValue, ok := secObject.Data[string(v1alpha1.SecretsManagerAzureClientSecret)]; ok {
			if err := os.Setenv("AZURE_CLIENT_SECRET", string(keyValue)); err != nil {
				return err
			}
		}
	}
	return nil

}

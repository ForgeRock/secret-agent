//go:build cloudprovider
// +build cloudprovider

package secretsmanager

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/keyvault/keyvault"
	azauth "github.com/Azure/azure-sdk-for-go/services/keyvault/auth"
	secretspb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
)

var (
	gcpProjectID   string
	azureVaultName string
)

func init() {
	projectID, ok := os.LookupEnv("GOOGLE_CLOUD_PROJECT")
	if !ok {
		log.Fatalf("GOOGLE_CLOUD_PROJECT environment variable required")
	}
	gcpProjectID = projectID
	vaultName, ok := os.LookupEnv("AZURE_VAULT_NAME")
	if ok {
		azureVaultName = vaultName
	} else {
		azureVaultName = "secret-agent-test"
	}

}

func TestLoadGCPSecrets(t *testing.T) {
	keyConfig := &v1alpha1.KeyConfig{
		Name: "username",
	}
	secretConfig := &v1alpha1.SecretConfig{
		Name:      "load-gcp-secrets",
		Namespace: "default",
		Keys:      []*v1alpha1.KeyConfig{keyConfig},
	}
	node := &v1alpha1.Node{
		Path:         []string{"load-gcp-secrets", "username"},
		SecretConfig: secretConfig,
	}
	nodes := []*v1alpha1.Node{node}

	// expect nothing found
	ctx := context.Background()
	err := loadGCPSecrets(ctx, gcpProjectID, nodes)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	if len(node.Value) != 0 {
		t.Fatalf("Expected no value, got: %d", len(node.Value))
	}

	// create secret to find
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	defer client.Close()
	secretID := "default_load-gcp-secrets_username"
	name := fmt.Sprintf("projects/%s/secrets/%s", gcpProjectID, secretID)
	createRequest := &secretspb.CreateSecretRequest{
		Parent:   fmt.Sprintf("projects/%s", gcpProjectID),
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
		t.Fatalf("Expected no error, got: %+v", err)
	}
	defer func() {
		deleteRequest := &secretspb.DeleteSecretRequest{Name: name}
		err := client.DeleteSecret(ctx, deleteRequest)
		if err != nil {
			t.Fatalf("Expected no error, got: %+v", err)
		}
	}()

	// find default_load-gcp-secrets_username
	// with no version
	err = loadGCPSecrets(ctx, gcpProjectID, nodes)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	if len(node.Value) != 0 {
		t.Fatalf("Expected no value, got: %d", len(node.Value))
	}
	// add version
	secretVersionRequest := &secretspb.AddSecretVersionRequest{
		Parent:  name,
		Payload: &secretspb.SecretPayload{Data: []byte("admin")},
	}
	_, err = client.AddSecretVersion(ctx, secretVersionRequest)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	err = loadGCPSecrets(ctx, gcpProjectID, nodes)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	if string(node.Value) != "admin" {
		t.Fatalf("Expected 'admin', got: %s", string(node.Value))
	}

}

func TestEnsureGCPSecrets(t *testing.T) {
	keyConfig := &v1alpha1.KeyConfig{
		Name: "username",
	}
	secretConfig := &v1alpha1.SecretConfig{
		Name:      "ensure-gcp-secrets",
		Namespace: "default",
		Keys:      []*v1alpha1.KeyConfig{keyConfig},
	}
	node := &v1alpha1.Node{
		Path:         []string{"ensure-gcp-secrets", "username"},
		SecretConfig: secretConfig,
		Value:        []byte("admin"),
	}
	nodes := []*v1alpha1.Node{node}

	// ensure default_ensure-gcp-secrets
	ctx := context.Background()
	err := ensureGCPSecrets(ctx, gcpProjectID, nodes)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	defer client.Close()
	secretID := "default_ensure-gcp-secrets_username"
	name := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", gcpProjectID, secretID)
	defer func() {
		name := fmt.Sprintf("projects/%s/secrets/%s", gcpProjectID, secretID)
		deleteRequest := &secretspb.DeleteSecretRequest{Name: name}
		err := client.DeleteSecret(ctx, deleteRequest)
		if err != nil {
			t.Fatalf("Expected no error, got: %+v", err)
		}
	}()
	// check result
	request := &secretspb.AccessSecretVersionRequest{Name: name}
	secretResponse, err := client.AccessSecretVersion(ctx, request)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	data := string(secretResponse.GetPayload().GetData())
	if data != "admin" {
		t.Fatalf("Expected 'admin', got: '%s'", data)
	}
}

// newAzureClient create an Azure client with an authorizer from the environment
func newCliAzureClient() (*keyvault.BaseClient, error) {
	authorizer, err := azauth.NewAuthorizerFromCLI()
	if err != nil {
		return &keyvault.BaseClient{}, err
	}
	client := keyvault.New()
	client.Authorizer = authorizer
	return &client, nil
}

// TestLoadAzure requires the vault to be pre-configured at the moment and for hard deletes too
// az keyvault create --name "secret-agent-test" --resource-group "secret-agent-test" --location eastus --enable-soft-delete false
func TestLoadAzure(t *testing.T) {
	keyConfig := &v1alpha1.KeyConfig{
		Name: "username",
	}
	secretConfig := &v1alpha1.SecretConfig{
		Name:      "load-azure-secrets",
		Namespace: "default",
		Keys:      []*v1alpha1.KeyConfig{keyConfig},
	}
	node := &v1alpha1.Node{
		Path:         []string{"load-azure-secrets", "username"},
		SecretConfig: secretConfig,
	}
	nodes := []*v1alpha1.Node{node}

	// expect nothing found
	baseCtx := context.Background()
	ctx1, cancel := context.WithTimeout(baseCtx, 3000000000)
	defer cancel()
	client, err := newCliAzureClient()
	if err != nil {
		t.Fatal(err)
	}

	err = loadAzureSecrets(ctx1, client, azureVaultName, nodes)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	if len(node.Value) != 0 {
		t.Fatalf("Expected no value, got: %+v", node.Value)
	}

	// create a secret to load
	ctx2, cancel := context.WithTimeout(baseCtx, 300000000)
	defer cancel()
	secretParams := keyvault.SecretSetParameters{}
	secretName := getSecretID(node.SecretConfig.Namespace, node.Path)
	secretValue := "test-value"
	secretParams.Value = &secretValue
	vaultURL := fmt.Sprintf(azureVaultURLFmt, azureVaultName)
	_, err = client.SetSecret(ctx2, vaultURL, secretName, secretParams)
	if err != nil {
		fmt.Printf("unable to add/update secret: %+v", err)
	}

	// cleanup vault
	defer func() {
		// delete
		_, err := client.DeleteSecret(baseCtx, vaultURL, secretName)
		if err != nil {
			t.Fatalf("Error deleting key from keyvault %s %s", vaultURL, secretName)
		}
	}()

	// test loaded secrets
	ctx3, cancel := context.WithTimeout(baseCtx, 300000000)
	defer cancel()
	err = loadAzureSecrets(ctx3, client, azureVaultName, nodes)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	if string(node.Value) != secretValue {
		t.Fatalf("Expected value to be: %s but found: %s", secretValue, string(node.Value))
	}

}

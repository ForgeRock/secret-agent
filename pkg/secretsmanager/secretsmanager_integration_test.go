// +build integration

package secretsmanager

import (
	"context"
	"fmt"
	"testing"

	"cloud.google.com/go/secretmanager/apiv1beta1"
	secretspb "google.golang.org/genproto/googleapis/cloud/secrets/v1beta1"
	"github.com/ForgeRock/secret-agent/pkg/types"
)

const (
	projectID = "fraas-integration-testing"
)

func TestLoadGCPSecrets(t *testing.T) {
	keyConfig := &types.KeyConfig{
		Name: "username",
	}
	secretConfig := &types.SecretConfig{
		Name:      "load-gcp-secrets",
		Namespace: "default",
		Keys:      []*types.KeyConfig{keyConfig},
	}
	node := &types.Node{
		Path:         []string{"load-gcp-secrets", "username"},
		SecretConfig: secretConfig,
	}
	nodes := []*types.Node{node}

	// expect nothing found
	ctx := context.Background()
	err := loadGCPSecrets(ctx, projectID, nodes)
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
	name := fmt.Sprintf("projects/%s/secrets/%s", projectID, secretID)
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
	err = loadGCPSecrets(ctx, projectID, nodes)
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
	err = loadGCPSecrets(ctx, projectID, nodes)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	if string(node.Value) != "admin" {
		t.Fatalf("Expected 'admin', got: %s", string(node.Value))
	}
}

func TestEnsureGCPSecrets(t *testing.T) {
	keyConfig := &types.KeyConfig{
		Name: "username",
	}
	secretConfig := &types.SecretConfig{
		Name:      "ensure-gcp-secrets",
		Namespace: "default",
		Keys:      []*types.KeyConfig{keyConfig},
	}
	node := &types.Node{
		Path:         []string{"ensure-gcp-secrets", "username"},
		SecretConfig: secretConfig,
		Value:        []byte("admin"),
	}
	nodes := []*types.Node{node}

	// ensure default_ensure-gcp-secrets
	ctx := context.Background()
	err := ensureGCPSecrets(ctx, projectID, nodes)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	defer client.Close()
	secretID := "default_ensure-gcp-secrets_username"
	name := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", projectID, secretID)
	defer func() {
		name := fmt.Sprintf("projects/%s/secrets/%s", projectID, secretID)
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

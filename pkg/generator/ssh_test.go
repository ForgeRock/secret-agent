package generator

import (
	"testing"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
)

func TestGenerateSSH(t *testing.T) {
	kc := &v1alpha1.KeyConfig{
		Name: "testConfig",
		Type: "ssh",
		Spec: &v1alpha1.KeySpec{},
	}
	ssh, err := NewSSH(kc)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
	err = ssh.Generate()
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
	if len(ssh.PrivateKeyPEM) == 0 {
		t.Errorf("Length of PrivateKeyPEM should be different than zero")
	}
	if len(ssh.PublicKeyPEM) == 0 {
		t.Errorf("Length of PublicKeyPEM should be different than zero")
	}
}

package generator

import (
	"testing"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
)

func TestGeneratePassword(t *testing.T) {
	kc := &v1alpha1.KeyConfig{
		Name: "testConfig",
		Type: "password",
		Spec: &v1alpha1.KeySpec{
			Length: nil,
		},
	}
	kc.Spec.Length = new(int)
	*kc.Spec.Length = 32
	password, err := NewPassword(kc)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
	err = password.Generate()
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
	if len(password.Value) != 32 {
		t.Errorf("Expected length 32, got: %d", len(password.Value))
	}
}

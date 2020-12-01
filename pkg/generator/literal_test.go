package generator

import (
	"testing"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
)

func TestGenerateLiteral(t *testing.T) {
	kc := &v1alpha1.KeyConfig{
		Name: "testConfig",
		Type: "literal",
		Spec: &v1alpha1.KeySpec{
			Value: "literal",
		},
	}
	literal := NewLiteral(kc)
	err := literal.Generate()
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
	if string(literal.Value) != "literal" {
		t.Errorf("Expected value was 'literal' but found %s", literal.Value)
	}
}

package v1alpha1

import (
	"testing"

	"github.com/go-playground/validator/v10"
)

func TestConfigurationStructLevelValidatorCA(t *testing.T) {
	key := &KeyConfig{
		Name: "foo",
		Type: KeyConfigTypeCA,
	}
	config := getConfig()
	config.Secrets[0].Keys = append(config.Secrets[0].Keys, key)
	validate := validator.New()
	validate.RegisterStructValidation(ConfigurationStructLevelValidator, SecretAgentConfigurationSpec{})
	err := validate.Struct(config)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
	// Spec must be empty
	key.Spec = new(KeySpec)
	config.Secrets[0].Keys[0] = key
	err = validate.Struct(config)
	if err == nil {
		t.Error("Spec must be empty: Expected error, got none")
	}
}

func TestConfigurationStructLevelValidatorLiteral(t *testing.T) {
	key := &KeyConfig{
		Name: "fdsa",
		Type: KeyConfigTypeLiteral,
	}
	config := getConfig()
	config.Secrets[0].Keys = append(config.Secrets[0].Keys, key)
	validate := validator.New()
	validate.RegisterStructValidation(ConfigurationStructLevelValidator, SecretAgentConfigurationSpec{})
	// Missing Value
	err := validate.Struct(config)
	if err == nil {
		t.Error("Missing Value: Expected error, got none")
	}
	// valid
	config.Secrets[0].Keys[0].Spec = new(KeySpec)
	config.Secrets[0].Keys[0].Spec.Value = "asdfKey"
	err = validate.Struct(config)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
}

func TestConfigurationStructLevelValidatorPassword(t *testing.T) {
	key := &KeyConfig{
		Name: "fdsa",
		Type: KeyConfigTypePassword,
	}
	config := getConfig()
	config.Secrets[0].Keys = append(config.Secrets[0].Keys, key)
	validate := validator.New()
	validate.RegisterStructValidation(ConfigurationStructLevelValidator, SecretAgentConfigurationSpec{})
	// Missing Length
	err := validate.Struct(config)
	if err == nil {
		t.Error("Missing Length: Expected error, got none")
	}
	// valid
	config.Secrets[0].Keys[0].Spec = new(KeySpec)
	config.Secrets[0].Keys[0].Spec.Length = new(int)
	*config.Secrets[0].Keys[0].Spec.Length = 16
	err = validate.Struct(config)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
}

func TestConfigurationStructLevelValidatorSSH(t *testing.T) {
	key := &KeyConfig{
		Name: "foo",
		Type: KeyConfigTypeSSH,
	}
	config := getConfig()
	config.Secrets[0].Keys = append(config.Secrets[0].Keys, key)
	validate := validator.New()
	validate.RegisterStructValidation(ConfigurationStructLevelValidator, SecretAgentConfigurationSpec{})
	err := validate.Struct(config)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
	// spec must be empty
	key.Spec = new(KeySpec)
	config.Secrets[0].Keys[0] = key
	err = validate.Struct(config)
	if err == nil {
		t.Error("Spec must be empty: Expected error, got none")
	}
}

func TestConfigurationStructLevelValidatorKeyPair(t *testing.T) {
	key := &KeyConfig{
		Name: "fdsaKey",
		Type: KeyConfigTypeKeyPair,
		Spec: &KeySpec{
			Algorithm:      "ECDSAWithSHA256",
			CommonName:     "name",
			Sans:           []string{"*.name", "*.name-repo", "*.name-cts"},
			SignedWithPath: "asdfSecret/ca",
		},
	}
	ca := &KeyConfig{
		Name: "ca",
		Type: KeyConfigTypeCA,
	}
	config := getConfig()
	config.Secrets[0].Keys = append(config.Secrets[0].Keys, key)
	config.Secrets[0].Keys = append(config.Secrets[0].Keys, ca)
	validate := validator.New()
	validate.RegisterStructValidation(ConfigurationStructLevelValidator, SecretAgentConfigurationSpec{})
	err := validate.Struct(config)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}

	// Missing Algorithm
	config.Secrets[0].Keys[0].Spec.Algorithm = ""
	err = validate.Struct(config)
	if err == nil {
		t.Error("Missing Algorithm: Expected error, got none")
	}
	config.Secrets[0].Keys[0].Spec.Algorithm = "ECDSAWithSHA256"

	// Missing CommonName
	config.Secrets[0].Keys[0].Spec.CommonName = ""
	err = validate.Struct(config)
	if err == nil {
		t.Error("Missing CommonName: Expected error, got none")
	}
	config.Secrets[0].Keys[0].Spec.CommonName = "name"

	// Missing SignedWith
	config.Secrets[0].Keys[0].Spec.SignedWithPath = ""
	err = validate.Struct(config)
	if err == nil {
		t.Error("Missing SignedWith: Expected error, got none")
	}
	config.Secrets[0].Keys[0].Spec.SignedWithPath = "asdfSecret/ca"

	// wrong SignedWith path
	config.Secrets[0].Keys[0].Spec.SignedWithPath = "asdfSecret/wrongSecretName"
	err = validate.Struct(config)
	if err == nil {
		t.Error("Wrong SignedWith: Expected error, got none")
	}
	config.Secrets[0].Keys[0].Spec.SignedWithPath = "asdfSecret/ca"

}

func TestConfigurationStructLevelValidatorTrustStore(t *testing.T) {
	key := &KeyConfig{
		Name: "fdsaKey",
		Type: KeyConfigTypeTrustStore,
		Spec: &KeySpec{
			TruststoreImportPaths: []string{"asdfSecret/badKey"},
		},
	}
	config := getConfig()
	config.Secrets[0].Keys = append(config.Secrets[0].Keys, key)
	validate := validator.New()
	validate.RegisterStructValidation(ConfigurationStructLevelValidator, SecretAgentConfigurationSpec{})
	// Missing PrivateKeyPath
	err := validate.Struct(config)
	if err == nil {
		t.Error("Missing PrivateKeyPath: Expected error, got none")
	}

	// Valid path
	key.Spec.TruststoreImportPaths = []string{"asdfSecret/fdsaKey"}
	config.Secrets[0].Keys[0] = key
	err = validate.Struct(config)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}

}

func TestConfigurationStructLevelValidatorKeytool(t *testing.T) {
	ca := &KeyConfig{
		Name: "ca",
		Type: KeyConfigTypeCA,
	}

	pwd := &KeyConfig{
		Name: "pwd",
		Type: KeyConfigTypePassword,
		Spec: &KeySpec{},
	}
	pwd.Spec.Length = new(int)
	*pwd.Spec.Length = 32

	keypair := &KeyConfig{
		Name: "keypa",
		Type: KeyConfigTypeKeyPair,
		Spec: &KeySpec{
			Algorithm:      "SHA256WithRSA",
			CommonName:     "name",
			SignedWithPath: "asdfSecret/ca",
		},
	}

	keytool := &KeyConfig{
		Name: "kt",
		Type: KeyConfigTypeKeytool,
		Spec: &KeySpec{
			StoreType:     "pkcs12",
			StorePassPath: "asdfSecret/pwd",
			KeyPassPath:   "asdfSecret/pwd",
			KeytoolAliases: []*KeytoolAliasConfig{
				{
					Name:       "ca-cert",
					Cmd:        "importcert",
					SourcePath: "asdfSecret/ca",
				},
				{
					Name:       "ssl-keypair",
					Cmd:        "importcert",
					SourcePath: "asdfSecret/keypa",
				},
				{
					Name:            "gentest",
					Cmd:             "genkeypair",
					Args:            []string{"yadayada", "foo", "bar"},
					DestinationPath: "asdfSecret/kt",
				},
			},
		},
	}
	config := getConfig()
	config.Secrets[0].Keys = append(config.Secrets[0].Keys, ca)
	config.Secrets[0].Keys = append(config.Secrets[0].Keys, pwd)
	config.Secrets[0].Keys = append(config.Secrets[0].Keys, keypair)
	config.Secrets[0].Keys = append(config.Secrets[0].Keys, keytool)
	validate := validator.New()
	validate.RegisterStructValidation(ConfigurationStructLevelValidator, SecretAgentConfigurationSpec{})
	err := validate.Struct(config)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}

	// Missing StoreType
	config.Secrets[0].Keys[3].Spec.StoreType = ""
	err = validate.Struct(config)
	if err == nil {
		t.Error("Missing StoreType: Expected error, got none")
	}
	config.Secrets[0].Keys[3].Spec.StoreType = "pkcs12"

	// Missing StorePassPath
	config.Secrets[0].Keys[3].Spec.StorePassPath = ""
	err = validate.Struct(config)
	if err == nil {
		t.Error("Missing StorePassPath: Expected error, got none")
	}
	config.Secrets[0].Keys[3].Spec.StorePassPath = "asdfSecret/pwd"

	// wrong StorePassPath
	config.Secrets[0].Keys[3].Spec.StorePassPath = "asdfSecret/wrongpath"
	err = validate.Struct(config)
	if err == nil {
		t.Error("Wrong StorePassPath: Expected error, got none")
	}
	config.Secrets[0].Keys[3].Spec.StorePassPath = "asdfSecret/pwd"

	// Missing KeyPassPath
	config.Secrets[0].Keys[3].Spec.KeyPassPath = ""
	err = validate.Struct(config)
	if err == nil {
		t.Error("Missing KeyPassPath: Expected error, got none")
	}
	config.Secrets[0].Keys[3].Spec.KeyPassPath = "asdfSecret/pwd"

	// wrong KeyPassPath
	config.Secrets[0].Keys[3].Spec.KeyPassPath = "asdfSecret/wrongpath"
	err = validate.Struct(config)
	if err == nil {
		t.Error("Wrong KeyPassPath: Expected error, got none")
	}
	config.Secrets[0].Keys[3].Spec.KeyPassPath = "asdfSecret/pwd"

	// Missing Alias SourcePath
	config.Secrets[0].Keys[3].Spec.KeytoolAliases[0].SourcePath = ""
	err = validate.Struct(config)
	if err == nil {
		t.Error("Missing Alias SourcePath: Expected error, got none")
	}
	config.Secrets[0].Keys[3].Spec.KeytoolAliases[0].SourcePath = "asdfSecret/ca"

	// wrong Alias SourcePath
	config.Secrets[0].Keys[3].Spec.KeytoolAliases[0].SourcePath = "asdfSecret/wrong"
	err = validate.Struct(config)
	if err == nil {
		t.Error("Wrong Alias SourcePath: Expected error, got none")
	}
	config.Secrets[0].Keys[3].Spec.KeytoolAliases[0].SourcePath = "asdfSecret/ca"

	// Missing Alias DestinationPath
	config.Secrets[0].Keys[3].Spec.KeytoolAliases[2].DestinationPath = ""
	err = validate.Struct(config)
	if err == nil {
		t.Error("Missing Alias DestinationPath: Expected error, got none")
	}
	config.Secrets[0].Keys[3].Spec.KeytoolAliases[2].DestinationPath = "asdfSecret/kt"

	// wrong Alias DestinationPath
	config.Secrets[0].Keys[3].Spec.KeytoolAliases[2].DestinationPath = "asdfSecret/wrong"
	err = validate.Struct(config)
	if err == nil {
		t.Error("Wrong Alias DestinationPath: Expected error, got none")
	}
	config.Secrets[0].Keys[3].Spec.KeytoolAliases[2].DestinationPath = "asdfSecret/kt"

	// Missing keytoolAliases
	config.Secrets[0].Keys[3].Spec.KeytoolAliases = nil
	err = validate.Struct(config)
	if err == nil {
		t.Error("Missing keytoolAliases: Expected error, got none")
	}
	config.Secrets[0].Keys[3].Spec.KeytoolAliases = keytool.Spec.KeytoolAliases
}

func TestConfigurationStructLevelValidatorDuplicateSecretName(t *testing.T) {
	key := &KeyConfig{
		Name: "foo",
		Type: KeyConfigTypeCA,
	}
	config := getConfig()
	config.Secrets[0].Keys = append(config.Secrets[0].Keys, key)
	// duplicate the secret
	config.Secrets = append(config.Secrets, config.Secrets[0])
	validate := validator.New()
	validate.RegisterStructValidation(ConfigurationStructLevelValidator, SecretAgentConfigurationSpec{})
	err := validate.Struct(config)
	if err == nil {
		t.Error("Expected error, got none")
	}

}
func TestConfigurationStructLevelValidatorDuplicateKeys(t *testing.T) {
	key := &KeyConfig{
		Name: "foo",
		Type: KeyConfigTypeCA,
	}
	config := getConfig()
	config.Secrets[0].Keys = append(config.Secrets[0].Keys, key)
	// duplicate the key
	config.Secrets[0].Keys = append(config.Secrets[0].Keys, key)
	validate := validator.New()
	validate.RegisterStructValidation(ConfigurationStructLevelValidator, SecretAgentConfigurationSpec{})
	err := validate.Struct(config)
	if err == nil {
		t.Error("Expected error, got none")
	}
}

func TestConfigurationStructLevelValidatorDuplicateKeytoolAlias(t *testing.T) {
}

func getConfig() *SecretAgentConfigurationSpec {
	return &SecretAgentConfigurationSpec{
		AppConfig: AppConfig{
			SecretsManager: SecretsManagerNone,
		},
		Secrets: []*SecretConfig{
			{
				Name:      "asdfSecret",
				Namespace: "default",
				Keys:      []*KeyConfig{},
			},
		},
	}
}

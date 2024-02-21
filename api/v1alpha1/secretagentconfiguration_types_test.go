package v1alpha1

import (
	"testing"

	"github.com/go-playground/validator/v10"
)

func TestConfigurationStructLevelValidatorCA(t *testing.T) {
	validate := validator.New()
	validate.RegisterStructValidation(ConfigurationStructLevelValidator, SecretAgentConfigurationSpec{})

	key := &KeyConfig{
		Name: "foo",
		Type: KeyConfigTypeCA,
		Spec: &KeySpec{
			Duration: nil,
			DistinguishedName: &DistinguishedName{
				CommonName: "bar",
			},
		},
	}
	config := getConfig()
	config.Secrets[0].Keys = append(config.Secrets[0].Keys, key)
	err := validate.Struct(config)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
}

func TestConfigurationStructLevelValidatorLiteral(t *testing.T) {
	key := &KeyConfig{
		Name: "fdsa",
		Type: KeyConfigTypeLiteral,
		Spec: &KeySpec{},
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
		Spec: &KeySpec{},
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
		Spec: &KeySpec{},
	}
	config := getConfig()
	config.Secrets[0].Keys = append(config.Secrets[0].Keys, key)
	validate := validator.New()
	validate.RegisterStructValidation(ConfigurationStructLevelValidator, SecretAgentConfigurationSpec{})
	err := validate.Struct(config)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
}

func TestConfigurationStructLevelValidatorKeyPair(t *testing.T) {
	key := &KeyConfig{
		Name: "fdsaKey",
		Type: KeyConfigTypeKeyPair,
		Spec: &KeySpec{
			Algorithm:         "ECDSAWithSHA256",
			Sans:              []string{"*.name", "*.name-repo", "*.name-cts"},
			SignedWithPath:    "asdfSecret/ca",
			DistinguishedName: &DistinguishedName{CommonName: "foo"},
		},
	}
	ca := &KeyConfig{
		Name: "ca",
		Type: KeyConfigTypeCA,
		Spec: &KeySpec{
			Duration: nil,
			DistinguishedName: &DistinguishedName{
				CommonName: "foo",
			},
		},
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
	config.Secrets[0].Keys[0].Spec.DistinguishedName = nil
	err = validate.Struct(config)
	if err == nil {
		t.Error("Missing DistinguishedName: Expected error, got none")
	}
	config.Secrets[0].Keys[0].Spec.DistinguishedName = &DistinguishedName{
		CommonName: "name",
	}

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
			TruststoreImportPaths: []string{"asdfSecret/externalKey"},
		},
	}
	config := getConfig()
	config.Secrets[0].Keys = append(config.Secrets[0].Keys, key)
	validate := validator.New()
	validate.RegisterStructValidation(ConfigurationStructLevelValidator, SecretAgentConfigurationSpec{})
	// Missing PrivateKeyPath
	err := validate.Struct(config)
	if err != nil {
		t.Errorf("Used external secret Expected no error, got one %+v", err)
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
		Spec: &KeySpec{
			Duration: nil,
			DistinguishedName: &DistinguishedName{
				CommonName: "bar",
			},
		},
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
			Algorithm: "SHA256WithRSA",
			DistinguishedName: &DistinguishedName{
				CommonName: "name",
			},
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
					Name: "gentest",
					Cmd:  "genkeypair",
					Args: []string{"yadayada", "foo", "bar"},
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
		Spec: &KeySpec{
			Duration: nil,
			DistinguishedName: &DistinguishedName{
				CommonName: "bar",
			},
		},
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
		Spec: &KeySpec{
			Duration: nil,
			DistinguishedName: &DistinguishedName{
				CommonName: "bar",
			},
		},
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
			SecretsManager:          SecretsManagerNone,
			CreateKubernetesObjects: true,
		},
		Secrets: []*SecretConfig{
			{
				Name: "asdfSecret",
				Keys: []*KeyConfig{},
			},
		},
	}
}

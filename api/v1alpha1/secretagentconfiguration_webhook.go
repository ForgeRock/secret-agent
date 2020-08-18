/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

// log is for logging in this package.
var log = logf.Log.WithName("secretagentconfiguration-webhook")

// SetupWebhookWithManager registers the webhook with the manager
func (r *SecretAgentConfiguration) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-secret-agent-secrets-forgerock-io-v1alpha1-secretagentconfiguration,mutating=true,failurePolicy=fail,groups=secret-agent.secrets.forgerock.io,resources=secretagentconfigurations,verbs=create;update,versions=v1alpha1,name=msecretagentconfiguration.kb.io

var _ webhook.Defaulter = &SecretAgentConfiguration{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *SecretAgentConfiguration) Default() {

	if r.Spec.AppConfig.MaxRetries == nil {
		r.Spec.AppConfig.MaxRetries = new(int)
		*r.Spec.AppConfig.MaxRetries = 3
	}

	if r.Spec.AppConfig.BackOffSecs == nil {
		r.Spec.AppConfig.BackOffSecs = new(int)
		*r.Spec.AppConfig.BackOffSecs = 2
	}

	for secretIndex, secret := range r.Spec.Secrets {
		if secret.GenerateIfNecessary == nil {
			r.Spec.Secrets[secretIndex].GenerateIfNecessary = new(bool)
			*r.Spec.Secrets[secretIndex].GenerateIfNecessary = true
		}
		for keysIndex, key := range secret.Keys {
			// If we're processing passwords and received no Spec, create a new spec.
			// We will be defaulting the Length
			if key.Spec == nil {
				r.Spec.Secrets[secretIndex].Keys[keysIndex].Spec = new(KeySpec)
			}

			if key.Type == KeyConfigTypePassword {
				r.Spec.Secrets[secretIndex].Keys[keysIndex].Spec.Length = new(int)
				*r.Spec.Secrets[secretIndex].Keys[keysIndex].Spec.Length = 32
			}
			if (key.Type == KeyConfigTypeCA || key.Type == KeyConfigTypeKeyPair) && key.Spec.Duration == nil {
				r.Spec.Secrets[secretIndex].Keys[keysIndex].Spec.Duration = new(metav1.Duration)
				r.Spec.Secrets[secretIndex].Keys[keysIndex].Spec.Duration.Duration = time.Duration(10 * 365 * 24 * time.Hour) //10yrs
			}
			r.Spec.Secrets[secretIndex].Keys[keysIndex].Spec.SignedWithPath = cleanUpPaths(key.Spec.SignedWithPath)
			r.Spec.Secrets[secretIndex].Keys[keysIndex].Spec.StorePassPath = cleanUpPaths(key.Spec.StorePassPath)
			r.Spec.Secrets[secretIndex].Keys[keysIndex].Spec.KeyPassPath = cleanUpPaths(key.Spec.KeyPassPath)
			for idx, path := range key.Spec.TruststoreImportPaths {
				r.Spec.Secrets[secretIndex].Keys[keysIndex].Spec.TruststoreImportPaths[idx] = cleanUpPaths(path)
			}
			for idx, alias := range key.Spec.KeytoolAliases {
				r.Spec.Secrets[secretIndex].Keys[keysIndex].Spec.KeytoolAliases[idx].SourcePath = cleanUpPaths(alias.SourcePath)
			}
		}
	}
}

func cleanUpPaths(p string) string {
	if p != "" {
		p = strings.TrimPrefix(p, PathDelimiter)
		p = strings.TrimSuffix(p, PathDelimiter)
	}
	return p
}

// change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// +kubebuilder:webhook:verbs=create;update,path=/validate-secret-agent-secrets-forgerock-io-v1alpha1-secretagentconfiguration,mutating=false,failurePolicy=fail,groups=secret-agent.secrets.forgerock.io,resources=secretagentconfigurations,versions=v1alpha1,name=vsecretagentconfiguration.kb.io

var _ webhook.Validator = &SecretAgentConfiguration{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *SecretAgentConfiguration) ValidateCreate() error {
	log.Info("Validating new SecretAgentConfiguration", "name", r.Name)
	return r.ValidateSecretConfiguration()
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *SecretAgentConfiguration) ValidateUpdate(old runtime.Object) error {
	log.Info("Validating existing SecretAgentConfiguration", "name", r.Name)
	return r.ValidateSecretConfiguration()
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *SecretAgentConfiguration) ValidateDelete() error {
	//We're not using this function atm. Keeping it here in case we do want to start using it later.
	return nil
}

// ValidateSecretConfiguration Validates the SecretAgentConfiguration object
func (r *SecretAgentConfiguration) ValidateSecretConfiguration() error {
	var err error
	validate := validator.New()
	validate.RegisterStructValidation(ConfigurationStructLevelValidator, SecretAgentConfigurationSpec{})
	if err = validate.Struct(&r.Spec); err != nil {
		return err
	}
	return nil

}

// ConfigurationStructLevelValidator ensures configuration is usable
func ConfigurationStructLevelValidator(sl validator.StructLevel) {
	config := sl.Current().Interface().(SecretAgentConfigurationSpec)

	// AppConfig
	switch config.AppConfig.SecretsManager {
	case SecretsManagerGCP:
		if config.AppConfig.GCPProjectID == "" {
			sl.ReportError(config.AppConfig.GCPProjectID, "gcpProjectID", "GCPProjectID", "emptyGCPProjectID", "")
		}
	case SecretsManagerAzure:
		if config.AppConfig.AzureVaultName == "" {
			sl.ReportError(config.AppConfig.AzureVaultName, "azureVaultName", "AzureVaultName", "emptyAzureVaultName", "")
		}
	case SecretsManagerAWS:
		if config.AppConfig.AWSRegion == "" {
			sl.ReportError(config.AppConfig.AWSRegion, "awsRegion", "AWSRegion", "emptyAWSRegion", "")
		}
	}

	// Secrets
	duplicateSecretName := make(map[string]bool)
	for secretIndex, secret := range config.Secrets {
		_, exist := duplicateSecretName[config.Secrets[secretIndex].Name]
		if !exist {
			duplicateSecretName[config.Secrets[secretIndex].Name] = true
		} else {
			sl.ReportError(config.Secrets[secretIndex], config.Secrets[secretIndex].Name,
				"Name", "duplicateSecretName", "")
			return
		}
		duplicateKeyName := make(map[string]bool)
		for keyIndex, key := range secret.Keys {
			name := fmt.Sprintf("Secrets.%s.%s",
				config.Secrets[secretIndex].Name,
				config.Secrets[secretIndex].Keys[keyIndex].Name,
			)
			_, exist := duplicateKeyName[config.Secrets[secretIndex].Keys[keyIndex].Name]
			if !exist {
				duplicateKeyName[config.Secrets[secretIndex].Keys[keyIndex].Name] = true
			} else {
				sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex],
					config.Secrets[secretIndex].Keys[keyIndex].Name, "Name", "duplicateKeyName", "")
				return
			}

			if key.Spec.UseBinaryCharacters && key.Type != KeyConfigTypePassword {
				sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Spec.UseBinaryCharacters, name,
					"useBinaryCharacters", "useBinaryCharactersNotAllowed", "")
				return
			}

			switch key.Type {
			case KeyConfigTypeCA:
				// must set DistinguishedName
				if key.Spec.DistinguishedName == nil || key.Spec.DistinguishedName.isEmpty() {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Spec.DistinguishedName, name,
						"distinguishedName", "distinguishedNameValueEmpty", "")
					return
				}
			case KeyConfigTypeLiteral:
				// must have Value
				if key.Spec.Value == "" {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Spec.Value, name,
						"value", "literalValueEmpty", "")
				}
			case KeyConfigTypePassword:
				// must have Length
				if key.Spec.Length == nil || *key.Spec.Length == 0 {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Spec.Length, name,
						"length", "passwordLengthZero", "")
				}
			// if type publicKeySSH, must have privateKey
			case KeyConfigTypeSSH:
				// must have empty spec. No extra specs should be specified
				if !key.Spec.isEmpty() {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Spec, name,
						"Spec", "specUnwantedValues", "")
				}
			case KeyConfigTypeKeyPair:
				// must set algorithm
				if key.Spec.Algorithm == "" {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Spec.Algorithm, name,
						"algorithm", "algorithmValueEmpty", "")
					return
				}
				// must set DistinguishedName
				if key.Spec.DistinguishedName == nil || key.Spec.DistinguishedName.isEmpty() {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Spec.DistinguishedName, name,
						"distinguishedName", "distinguishedNameValueEmpty", "")
					return

				}
				// must set signedWith
				if key.Spec.SignedWithPath == "" {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Spec.SignedWithPath, name,
						"signedWith", "signedWithValueEmpty", "")
					return
				}
				// signedWith path must be valid
				if !pathExistsInSecretAgentConfiguration(key.Spec.SignedWithPath, config.Secrets) {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Spec.SignedWithPath, name,
						"signedWith", "signedWithInvalidPath", "")
					return
				}

			case KeyConfigTypeTrustStore:
				if len(key.Spec.TruststoreImportPaths) == 0 {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Spec.TruststoreImportPaths, name,
						"truststoreImportPaths", "truststoreImportPathsValueEmpty", "")
					return
				}

				for aliasIndex, alias := range key.Spec.TruststoreImportPaths {
					if !pathExistsInSecretAgentConfiguration(alias, config.Secrets) {
						sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Spec.TruststoreImportPaths[aliasIndex], name,
							"truststoreImportPaths", "truststoreImportPathsNotFound", "")
						return
					}

				}
			case KeyConfigTypeKeytool:
				// must set storeType
				if key.Spec.StoreType == "" {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Spec.StorePassPath, name,
						"storeType", "storeTypeValueEmpty", "")
				}
				// must have keyPassPath
				if len(key.Spec.KeyPassPath) == 0 {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Spec.KeyPassPath, name,
						"keyPassPath", "keyPassPathNotFound", "")
					return
				}
				// keyPassPath must be valid
				if !pathExistsInSecretAgentConfiguration(key.Spec.KeyPassPath, config.Secrets) {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Spec.KeyPassPath, name,
						"keyPassPath", "keyPassPathNotValid", "")
					return
				}
				// must have storePassPath
				if len(key.Spec.StorePassPath) == 0 {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Spec.StorePassPath, name,
						"storePassPath", "storePassPathNotFound", "")
					return
				}
				// storePassPath must be valid
				if !pathExistsInSecretAgentConfiguration(key.Spec.StorePassPath, config.Secrets) {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Spec.StorePassPath, name,
						"storePassPath", "storePassPathNotValid", "")
					return
				}
				// must have KeytoolAliases
				if len(key.Spec.KeytoolAliases) == 0 {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Spec.KeytoolAliases, name,
						"keytoolAliases", "keytoolAliasesNotSet", "")
					return
				}
				duplicateAliasName := make(map[string]bool)
				for aliasIndex, alias := range key.Spec.KeytoolAliases {
					_, exist := duplicateAliasName[config.Secrets[secretIndex].Keys[keyIndex].Spec.KeytoolAliases[aliasIndex].Name]
					if !exist {
						duplicateAliasName[config.Secrets[secretIndex].Keys[keyIndex].Spec.KeytoolAliases[aliasIndex].Name] = true
					} else {
						sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Spec.KeytoolAliases[aliasIndex],
							config.Secrets[secretIndex].Keys[keyIndex].Spec.KeytoolAliases[aliasIndex].Name,
							"Name", "duplicateAliasName", "")
						return
					}
					name := fmt.Sprintf("Secrets.%s.%s.%s",
						config.Secrets[secretIndex].Name,
						config.Secrets[secretIndex].Keys[keyIndex].Name,
						config.Secrets[secretIndex].Keys[keyIndex].Spec.KeytoolAliases[aliasIndex].Name,
					)
					switch alias.Cmd {
					case KeytoolCmdImportcert, KeytoolCmdImportpassword:
						if alias.SourcePath == "" {
							sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Spec.KeytoolAliases[aliasIndex],
								name, "sourcePass", "sourcePassNotSet", "")
							return
						}
						if !pathExistsInSecretAgentConfiguration(alias.SourcePath, config.Secrets) {
							sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Spec.KeytoolAliases[aliasIndex].SourcePath,
								name, "sourcePath", "sourcePathNotValid", "")
							return
						}
					case KeytoolCmdGenkeypair, KeytoolCmdGenseckey:
						if len(alias.Args) == 0 {
							sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Spec.KeytoolAliases[aliasIndex],
								name, "args", "argsNotSet", "")
							return
						}

					}

				}
			}
		}
	}
}

func pathExistsInSecretAgentConfiguration(path string, secrets []*SecretConfig) bool {
	secretIdx := -1

	iterator := reflect.ValueOf(secrets)
	pathSlice := strings.Split(path, PathDelimiter)
	for _, pathSliceMember := range pathSlice {
		for idx := 0; idx < iterator.Len(); idx++ {
			// if the "Name" field of the iterator matches the pathSliceMember
			if iterator.Index(idx).Elem().FieldByName("Name").Interface() == pathSliceMember {
				// we must have found the secret. Will continue with the keys of that secret
				if secretIdx == -1 {
					secretIdx = idx
					iterator = iterator.Index(idx).Elem().FieldByName("Keys")
					break
				} else {
					// We already found the secret previously and now found the key
					return true
				}
			}
		}
		// No secret names matched. No need to continue matching checking the pathSlice
		if secretIdx == -1 {
			break
		}
	}
	return false
}

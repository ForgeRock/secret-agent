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

	"github.com/go-playground/validator/v10"
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
	// log.Info("default", "name", r.Name)
	// TODO LATER: fill in defaulting logic here if we ever want to.
	//example
	// if r.Spec.AppConfig.SecretsManager == "" {
	// 	r.Spec.AppConfig.SecretsManager = SecretsManagerNone
	// }
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
	for secretIndex, secret := range config.Secrets {
		for keyIndex, key := range secret.Keys {
			switch key.Type {
			case TypeLiteral:
				// must have Value
				if key.Value == "" {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Value, "value", "Value", "literalValueEmpty", "")
				}
			case TypePassword:
				// must have Length
				if key.Length == 0 {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Length, "length", "Length", "passwordLengthZero", "")
				}
			// if type publicKeySSH, must have privateKey
			case TypePublicKeySSH:
				name := fmt.Sprintf("Secrets.%s.%s",
					config.Secrets[secretIndex].Name,
					config.Secrets[secretIndex].Keys[keyIndex].Name,
				)
				// must have privateKeyPath
				if len(key.PrivateKeyPath) == 0 {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].PrivateKeyPath, name, "PrivateKeyPath", "privateKeyPathNotSet", "")
					return
				}
				// privateKeyPath must be valid
				if !pathExistsInSecretConfigs(key.PrivateKeyPath, config.Secrets) {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].PrivateKeyPath, name, "PrivateKeyPath", "privateKeyPathNotFound", "")
				}
			case TypePKCS12:
				name := fmt.Sprintf("Secrets.%s.%s",
					config.Secrets[secretIndex].Name,
					config.Secrets[secretIndex].Keys[keyIndex].Name,
				)
				// must have keystoreAliases
				if len(key.AliasConfigs) == 0 {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].AliasConfigs, name, "AliasConfigs", "keystoreAliasesNotSet", "")
					return
				}
				// must have keyPassPath
				if len(key.KeyPassPath) == 0 {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].KeyPassPath, name, "KeyPassPath", "keyPassPathNotFound", "")
					return
				}
				// keyPassPath must be valid
				if !pathExistsInSecretConfigs(key.KeyPassPath, config.Secrets) {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].KeyPassPath, name, "KeyPassPath", "keyPassPathNotValid", "")
					return
				}
				// must have storePassPath
				if len(key.StorePassPath) == 0 {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].StorePassPath, name, "StorePassPath", "storePassPathNotFound", "")
					return
				}
				// storePassPath must be valid
				if !pathExistsInSecretConfigs(key.StorePassPath, config.Secrets) {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].KeyPassPath, name, "StorePassPath", "storePassPathNotValid", "")
					return
				}
				for aliasIndex, alias := range key.AliasConfigs {
					switch alias.Type {
					case TypeCA:
						name := fmt.Sprintf("Secrets.%s.%s.%s",
							config.Secrets[secretIndex].Name,
							config.Secrets[secretIndex].Keys[keyIndex].Name,
							config.Secrets[secretIndex].Keys[keyIndex].AliasConfigs[aliasIndex].Alias,
						)
						// must have passwordPath
						if len(alias.PasswordPath) == 0 {
							sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].AliasConfigs[aliasIndex].Alias, name, "CA", "passwordPathNotSet", "")
							return
						}
						// passwordPath must be valid
						if !pathExistsInSecretConfigs(alias.PasswordPath, config.Secrets) {
							sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].AliasConfigs[aliasIndex].Alias, name, "CA", "passwordPathNotFound", "")
							return
						}
					}
				}
			}
		}
	}
}

func pathExistsInSecretConfigs(path []string, secrets []*SecretConfig) bool {
	found := false
path:
	for _, secret := range secrets {
		if secret.Name == path[0] {
			for _, key := range secret.Keys {
				if key.Name == path[1] {
					if len(path) == 2 {
						found = true
						break path
					}
					for _, alias := range key.AliasConfigs {
						if alias.Alias == path[2] {
							found = true
							break path
						}
					}
				}
			}
		}
	}

	return found
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
	case SecretsManagerAWS:
		if config.AppConfig.AWSRegion == "" {
			sl.ReportError(config.AppConfig.AWSRegion, "awsRegion", "AWSRegion", "emptyAWSRegion", "")
		}
	}

	// Secrets
	for secretIndex, secret := range config.Secrets {
		for keyIndex, key := range secret.Keys {
			switch key.Type {
			case TypeLiteral:
				// must have Value
				if key.Value == "" {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Value, "value", "Value", "literalValueEmpty", "")
				}
			case TypePassword:
				// must have Length
				if key.Length == 0 {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].Length, "length", "Length", "passwordLengthZero", "")
				}
			// if type publicKeySSH, must have privateKey
			case TypePublicKeySSH:
				name := fmt.Sprintf("Secrets.%s.%s",
					config.Secrets[secretIndex].Name,
					config.Secrets[secretIndex].Keys[keyIndex].Name,
				)
				// must have privateKeyPath
				if len(key.PrivateKeyPath) == 0 {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].PrivateKeyPath, name, "PrivateKeyPath", "privateKeyPathNotSet", "")
					return
				}
				// privateKeyPath must be valid
				if !pathExistsInSecretConfigs(key.PrivateKeyPath, config.Secrets) {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].PrivateKeyPath, name, "PrivateKeyPath", "privateKeyPathNotFound", "")
				}
			case TypePKCS12:
				name := fmt.Sprintf("Secrets.%s.%s",
					config.Secrets[secretIndex].Name,
					config.Secrets[secretIndex].Keys[keyIndex].Name,
				)
				// must have keystoreAliases
				if len(key.AliasConfigs) == 0 {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].AliasConfigs, name, "AliasConfigs", "keystoreAliasesNotSet", "")
					return
				}
				// must have keyPassPath
				if len(key.KeyPassPath) == 0 {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].KeyPassPath, name, "KeyPassPath", "keyPassPathNotFound", "")
					return
				}
				// keyPassPath must be valid
				if !pathExistsInSecretConfigs(key.KeyPassPath, config.Secrets) {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].KeyPassPath, name, "KeyPassPath", "keyPassPathNotValid", "")
					return
				}
				// must have storePassPath
				if len(key.StorePassPath) == 0 {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].StorePassPath, name, "StorePassPath", "storePassPathNotFound", "")
					return
				}
				// storePassPath must be valid
				if !pathExistsInSecretConfigs(key.StorePassPath, config.Secrets) {
					sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].KeyPassPath, name, "StorePassPath", "storePassPathNotValid", "")
					return
				}
				for aliasIndex, alias := range key.AliasConfigs {
					name := fmt.Sprintf("Secrets.%s.%s.%s",
						config.Secrets[secretIndex].Name,
						config.Secrets[secretIndex].Keys[keyIndex].Name,
						config.Secrets[secretIndex].Keys[keyIndex].AliasConfigs[aliasIndex].Alias,
					)
					switch alias.Type {
					case TypePEMPublicKeyCopy:
						// must have publicKeyPath
						if len(alias.PublicKeyPath) == 0 {
							sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].AliasConfigs[aliasIndex].Alias, name, "PEMPublicKeyCopy", "publicKeyPathNotSet", "")
							return
						}
						// publicKeyPath must be valid
						if !pathExistsInSecretConfigs(alias.PublicKeyPath, config.Secrets) {
							sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].AliasConfigs[aliasIndex].Alias, name, "PEMPublicKeyCopy", "publicKeyPathNotFound", "")
							return
						}
					case TypeKeyPair:
						// must have signedWithPath
						if len(alias.SignedWithPath) == 0 {
							sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].AliasConfigs[aliasIndex].Alias, name, "KeyPair", "signedWithPathNotSet", "")
							return
						}
						// signedWithPath must be valid
						if !pathExistsInSecretConfigs(alias.SignedWithPath, config.Secrets) {
							sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].AliasConfigs[aliasIndex].Alias, name, "KeyPair", "signedWithPathNotFound", "")
							return
						}
						// must have algorithm
						if len(alias.Algorithm) == 0 {
							sl.ReportError(config.Secrets[secretIndex].Keys[keyIndex].AliasConfigs[aliasIndex].Alias, name, "KeyPair", "algorithmNotSet", "")
							return
						}
					}
				}
			}
		}
	}
}

func pathExistsInSecretConfigs(path []string, secrets []*SecretConfig) bool {
	found := false
path:
	for _, secret := range secrets {
		if secret.Name == path[0] {
			for _, key := range secret.Keys {
				if key.Name == path[1] {
					if len(path) == 2 {
						found = true
						break path
					}
					for _, alias := range key.AliasConfigs {
						if alias.Alias == path[2] {
							found = true
							break path
						}
					}
				}
			}
		}
	}

	return found
}

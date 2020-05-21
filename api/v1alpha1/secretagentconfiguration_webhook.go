/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"github.com/go-playground/validator/v10"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

// log is for logging in this package.
var log = logf.Log.WithName("secretagentconfiguration-webhook")

//SetupWebhookWithManager registers the webhook with the manager
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
	// TODO: fill in defaulting logic here.
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
	log.Info("validate delete", "name", r.Name)
	return nil
}

//ValidateSecretConfiguration Validates the SecretAgentConfiguration object
func (r *SecretAgentConfiguration) ValidateSecretConfiguration() error {
	var err error
	validate := validator.New()
	validate.RegisterStructValidation(ConfigurationStructLevelValidator, SecretAgentConfigurationSpec{})
	if err = validate.Struct(&r.Spec); err != nil {
		log.Error(err, "Validation failed")
	}
	return err

}

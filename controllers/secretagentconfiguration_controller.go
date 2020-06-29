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

package controllers

import (
	"context"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"

	"github.com/ForgeRock/secret-agent/pkg/generator"
	"github.com/ForgeRock/secret-agent/pkg/k8ssecrets"
	corev1 "k8s.io/api/core/v1"
	k8serror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SecretAgentConfigurationReconciler reconciles a SecretAgentConfiguration object
type SecretAgentConfigurationReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=secret-agent.secrets.forgerock.io,resources=secretagentconfigurations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=secret-agent.secrets.forgerock.io,resources=secretagentconfigurations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingwebhookconfigurations;mutatingwebhookconfigurations,verbs=get;update;patch

// Reconcile reconcile loop for CRD controller
func (reconciler *SecretAgentConfigurationReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := reconciler.Log.WithValues("secretagentconfiguration", req.NamespacedName)

	// TODO update for new spec
	var instance v1alpha1.SecretAgentConfiguration
	if err := reconciler.Get(ctx, req.NamespacedName, &instance); err != nil {
		if k8serror.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return ctrl.Result{}, nil
		}
		log.Error(err, "unable to fetch SecretAgentConfiguration")
		return ctrl.Result{}, err
	}
	for _, secretReq := range instance.Spec.Secrets {
		// load from secret k8s
		secObject, err := k8ssecrets.LoadSecret(reconciler.Client, secretReq.Name, instance.Namespace)
		if err != nil {
			log.Error(err, "error loading existing secrets from the Kubernetes API",
				"secret_name", secretReq.Name,
				"namespace", instance.Namespace)
			return ctrl.Result{}, err
		}
		log.Info("reconciling secret", "secret_name", secretReq.Name)
		var keyInterface generator.KeyMgr
	secretKeys:
		for _, key := range secretReq.Keys {
			switch key.Type {
			case v1alpha1.KeyConfigTypeCA:
				log.Info("reconciling secret",
					"secret_name", secretReq.Name,
					"data_key", key.Name,
					"secret_type", string(key.Type))
				keyInterface = generator.NewRootCA()
			case v1alpha1.KeyConfigTypeKeyPair:
				log.Info("reconciling secret",
					"secret_name", secretReq.Name,
					"data_key", key.Name,
					"secret_type", string(key.Type))
				keyInterface, err = generator.NewCertKeyPair(key)
				if err != nil {
					log.Error(err, "error looking up secret ref",
						"secret_name", secretReq.Name,
						"data_key", key.Name,
						"secret_type", string(key.Type))
				}
			default:
				// We continue through all keys in a secret skipping unsupported types
				log.Info("secret type not implemented skipping key",
					"secret_name", secretReq.Name,
					"data_key", key.Name,
					"secret_type", string(key.Type))
				break secretKeys
			}
			// load from secret manager
			useSecMgr := instance.Spec.AppConfig.SecretsManager != v1alpha1.SecretsManagerNone
			if useSecMgr {
				log.Info("loading secret from secret-manager",
					"secret_name", secretReq.Name,
					"data_key", key.Name,
					"secret_type", string(key.Type))
				keyInterface.LoadSecretFromManager(ctx, &instance.Spec.AppConfig, instance.Namespace, key.Name)
			} else {
				// load from kubernetes
				log.Info("loading secret from kubernetes",
					"secret_name", secretReq.Name,
					"data_key", key.Name,
					"secret_type", string(key.Type))
				keyInterface.LoadFromData(secObject.Data)
			}

			// Load key references and data
			var keyRefSecrets []map[string][]byte
			refs, _ := keyInterface.References()
			for _, ref := range refs {
				secRefObject, err := k8ssecrets.LoadSecret(reconciler.Client, ref, instance.Namespace)
				if err != nil {
					log.Error(err, "error looking up secret ref",
						"secret_name", secretReq.Name,
						"secret_ref", ref)
				}
				if (&corev1.Secret{}) == secObject {
					log.Error(err, "secret ref not found, skipping key",
						"secret_name", secretReq.Name,
						"secret_ref", ref)
					break secretKeys
				}
				keyRefSecrets = append(keyRefSecrets, secRefObject.Data)

			}
			if err := keyInterface.LoadReferenceData(keyRefSecrets); err != nil {
				log.Error(err, "error loading references skipping key",
					"secret_name", secretReq.Name,
					"data_key", key.Name,
					"secret_type", string(key.Type))
				break secretKeys
			}

			// Generate and apply to secret manager
			if keyInterface.IsEmpty() {
				log.Info("no secret data found, generating",
					"secret_name", secretReq.Name,
					"data_key", key.Name,
					"secret_type", string(key.Type))
				err := keyInterface.Generate()
				if err != nil {
					log.Error(err, "error generating secret",
						"secret_name", secretReq.Name,
						"data_key", key.Name,
						"secret_type", string(key.Type))
					break secretKeys
				}
				if useSecMgr {
					log.Info("storing secret to secret-manager",
						"secret_name", secretReq.Name,
						"data_key", key.Name,
						"secret_type", string(key.Type))
					keyInterface.EnsureSecretManager(ctx, &instance.Spec.AppConfig,
						instance.Namespace, key.Name)
				}
			}

			// apply, updates per key, do we want to wait until the end (could crash and lose the whole secret)
			log.Info("applying to kubernetes",
				"secret_name", secretReq.Name,
				"data_key", key.Name,
				"secret_type", string(key.Type))
			keyInterface.ToKubernetes(secObject)
			op, err := k8ssecrets.ApplySecrets(reconciler.Client, secObject)
			if err != nil {
				log.Error(err, "couldnt apply secret",
					"method", op,
					"secret_namespace", instance.Namespace,
					"secret_name", secretReq.Name)
			}
			log.Info("completed reconcile",
				"method", op,
				"secret_namespace", instance.Namespace,
				"secret_name", secretReq.Name)
		}
	}
	return ctrl.Result{}, nil
}

var (
	jobOwnerKey = ".metadata.controller"
	apiGVStr    = v1alpha1.GroupVersion.String()
)

// SetupWithManager is used to register the reconciler to the manager
func (reconciler *SecretAgentConfigurationReconciler) SetupWithManager(mgr ctrl.Manager) error {

	if err := mgr.GetFieldIndexer().IndexField(&corev1.Secret{}, jobOwnerKey, func(rawObj runtime.Object) []string {
		// grab the secret object, extract the owner...
		secret := rawObj.(*corev1.Secret)
		owner := metav1.GetControllerOf(secret)
		if owner == nil {
			return nil
		}
		// ...make sure it's a SecretAgentConfiguration...
		if owner.APIVersion != apiGVStr || owner.Kind != "SecretAgentConfiguration" {
			return nil
		}

		// ...and if so, return it
		return []string{owner.Name}
	}); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.SecretAgentConfiguration{}).
		Owns(&corev1.Secret{}).
		Complete(reconciler)

}

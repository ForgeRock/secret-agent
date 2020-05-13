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
	"reflect"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	secretagentv1alpha1 "github.com/ForgeRock/secret-agent/api/v1alpha1"

	"github.com/ForgeRock/secret-agent/pkg/generator"
	"github.com/ForgeRock/secret-agent/pkg/k8ssecrets"
	"github.com/ForgeRock/secret-agent/pkg/memorystore"
	"github.com/ForgeRock/secret-agent/pkg/secretsmanager"
	secretagenttypes "github.com/ForgeRock/secret-agent/pkg/types" //TODO: Part of datatype workaround
	"github.com/go-playground/validator/v10"
	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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

// Reconcile function
func (r *SecretAgentConfigurationReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("secretagentconfiguration", req.NamespacedName)

	// your logic here
	var instance secretagentv1alpha1.SecretAgentConfiguration
	if err := r.Get(ctx, req.NamespacedName, &instance); err != nil {
		log.Error(err, "unable to fetch SecretAgentConfiguration")
		// we'll ignore not-found errors, since they can't be fixed by an immediate
		// requeue (we'll need to wait for a new notification), and we can get them
		// on deleted requests.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	//Old main.go

	// TODO Datatype workaround
	data, err := yaml.Marshal(instance.Spec)
	config := &secretagenttypes.Configuration{}
	err = yaml.Unmarshal(data, config)
	//

	//Namespace workaround: Populate the namespace field. Expected by downstream functions.
	for index := range config.Secrets {
		config.Secrets[index].Namespace = instance.Namespace
	}

	//TODO Change to validating webhook: https://book.kubebuilder.io/cronjob-tutorial/webhook-implementation.html
	validate := validator.New()
	validate.RegisterStructValidation(secretagentv1alpha1.ConfigurationStructLevelValidator, secretagentv1alpha1.Configuration{})
	err = validate.Struct(config)
	if err != nil {
		log.Error(err, "error validating configuration file: %+v")
	}

	clientSet, err := k8ssecrets.GetClientSet()
	if err != nil {
		log.Error(err, "error getting Kubernetes ClientSet: %+v")
	}

	nodes := memorystore.GetDependencyNodes(config)
	err = memorystore.EnsureAcyclic(nodes)
	if err != nil {
		log.Error(err, "%+v")
	}
	// EnsureAcyclic works by removing leaf nodes from the set of nodes, so we need to regenerate the set
	//   copy(src, dst) is not good enough, because the nodes get modified along the way
	nodes = memorystore.GetDependencyNodes(config)

	if config.AppConfig.SecretsManager != secretagenttypes.SecretsManagerNone {
		err := secretsmanager.LoadExisting(ctx, config, nodes)
		if err != nil {
			log.Error(err, "error loading existing secrets from the Secrets Manager: %+v")
		}
	}

	err = k8ssecrets.LoadExisting(clientSet, config.Secrets)
	if err != nil {
		log.Error(err, "error loading existing secrets from the Kubernetes API: %+v")
	}

	for _, node := range nodes {
		err = generator.RecursivelyGenerateIfMissing(config, node)
		if err != nil {
			log.Error(err, "error generating secrets: %+v")
		}
	}

	if config.AppConfig.SecretsManager != secretagenttypes.SecretsManagerNone {
		err = secretsmanager.EnsureSecrets(ctx, config, nodes)
		if err != nil {
			log.Error(err, "error ensuring secrets in the Secrets Manager: %+v")
		}
	}

	//end old main.go

	k8sSecrets := k8ssecrets.GenerateSecretAPIObjects(config.Secrets)

	labelsForSecretAgent := func(name string) map[string]string {
		return map[string]string{"managed-by-secret-agent": "true", "secret-agent-configuration-name": name}
	}

	if instance.Spec.AppConfig.CreateKubernetesObjects {
		for _, secret := range k8sSecrets {
			// Set SecretAgentConfiguration instance as the owner and controller of the secret
			if err := ctrl.SetControllerReference(&instance, secret, r.Scheme); err != nil {
				return ctrl.Result{}, err
			}

			found := &corev1.Secret{}
			if err := r.Get(ctx, types.NamespacedName{Name: secret.Name, Namespace: secret.Namespace}, found); err == nil { // The secret is there, we just need to update it
				if !reflect.DeepEqual(secret.Data, found.Data) {
					log.Info("Secret data has changed. Updating", "Secret.Namespace", secret.Namespace, "Secret.Name", secret.Name)
					secret.Labels = labelsForSecretAgent(instance.Name) //Update secret labels

					if err := r.Update(ctx, secret); err != nil {
						return ctrl.Result{}, err
					}
				} else {
					log.Info("Secret data is consistent. Doing nothing", "Secret.Namespace", secret.Namespace, "Secret.Name", secret.Name)
				}
			} else if err != nil && errors.IsNotFound(err) {
				log.Info("Creating a new Secret", "Secret.Namespace", secret.Namespace, "Secret.Name", secret.Name)
				secret.Labels = labelsForSecretAgent(instance.Name) //Update secret labels

				if err := r.Create(ctx, secret); err != nil {
					log.Error(err, "unable to create secret", "secret", secret)
					return ctrl.Result{}, err
				}
			}
		}
	}

	// Update the SecretAgentConfiguration status with the object names
	secretList := &corev1.SecretList{}
	listOpts := []client.ListOption{
		client.InNamespace(instance.Namespace),
		client.MatchingLabels(labelsForSecretAgent(instance.Name)),
	}
	if err := r.List(ctx, secretList, listOpts...); err != nil {
		log.Error(err, "Failed to list secrets", "Namespace", instance.Namespace, "SecretAgentConfiguration", instance.Name)
		return ctrl.Result{}, err
	}
	var secretNames []string
	for _, secret := range secretList.Items {
		secretNames = append(secretNames, secret.Name)
	}
	totalManagedObjects := len(secretNames) // TODO Need to add AWS + GCP resources
	// Update status.k8sSecrets
	if !reflect.DeepEqual(secretNames, instance.Status.ManagedK8sSecrets) || instance.Status.TotalManagedObjects != totalManagedObjects {
		instance.Status.ManagedK8sSecrets = secretNames
		instance.Status.TotalManagedObjects = totalManagedObjects

		if err := r.Status().Update(ctx, &instance); err != nil {
			log.Error(err, "Failed to update SecretAgentConfiguration status")
			return ctrl.Result{}, err
		}
	}

	////
	return ctrl.Result{}, nil
}

var (
	jobOwnerKey = ".metadata.controller"
	apiGVStr    = secretagentv1alpha1.GroupVersion.String()
)

//SetupWithManager is used to register the reconciler to the manager
func (r *SecretAgentConfigurationReconciler) SetupWithManager(mgr ctrl.Manager) error {

	if err := mgr.GetFieldIndexer().IndexField(&corev1.Secret{}, jobOwnerKey, func(rawObj runtime.Object) []string {
		// grab the secret object, extract the owner...
		secret := rawObj.(*corev1.Secret)
		owner := metav1.GetControllerOf(secret)
		if owner == nil {
			return nil
		}
		// ...make sure it's a CronJob...
		if owner.APIVersion != apiGVStr || owner.Kind != "SecretAgentConfiguration" {
			return nil
		}

		// ...and if so, return it
		return []string{owner.Name}
	}); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&secretagentv1alpha1.SecretAgentConfiguration{}).
		Owns(&corev1.Secret{}).
		Complete(r)

}

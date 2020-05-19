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
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"

	"github.com/ForgeRock/secret-agent/pkg/generator"
	"github.com/ForgeRock/secret-agent/pkg/k8ssecrets"
	"github.com/ForgeRock/secret-agent/pkg/memorystore"
	"github.com/ForgeRock/secret-agent/pkg/secretsmanager"
	"github.com/go-playground/validator/v10"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
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

// Reconcile function
func (reconciler *SecretAgentConfigurationReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := reconciler.Log.WithValues("secretagentconfiguration", req.NamespacedName)

	// your logic here
	var instance v1alpha1.SecretAgentConfiguration
	if err := reconciler.Get(ctx, req.NamespacedName, &instance); err != nil {

		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return ctrl.Result{}, nil
		}
		log.Error(err, "unable to fetch SecretAgentConfiguration")
		return ctrl.Result{}, err
	}

	//Old main.go

	//Populate the Namespace field. All secrets are created in the namespace of the SecretAgentConfiguration
	for index := range instance.Spec.Secrets {
		instance.Spec.Secrets[index].Namespace = instance.Namespace
	}

	//TODO Change to validating webhook: https://book.kubebuilder.io/cronjob-tutorial/webhook-implementation.html
	validate := validator.New()
	validate.RegisterStructValidation(v1alpha1.ConfigurationStructLevelValidator, v1alpha1.SecretAgentConfigurationSpec{})

	if err := validate.Struct(&instance.Spec); err != nil {
		log.Error(err, "error validating configuration file: %+v")
		return ctrl.Result{}, err
	}

	nodes := memorystore.GetDependencyNodes(&instance.Spec)
	if err := memorystore.EnsureAcyclic(nodes); err != nil {
		log.Error(err, "%+v")
		return ctrl.Result{}, err
	}
	// EnsureAcyclic works by removing leaf nodes from the set of nodes, so we need to regenerate the set
	//   copy(src, dst) is not good enough, because the nodes get modified along the way
	nodes = memorystore.GetDependencyNodes(&instance.Spec)

	if instance.Spec.AppConfig.SecretsManager != v1alpha1.SecretsManagerNone {
		err := secretsmanager.LoadExisting(ctx, &instance.Spec, nodes)
		if err != nil {
			log.Error(err, "error loading existing secrets from the Secrets Manager: %+v")
			return ctrl.Result{}, err
		}
	}

	if err := k8ssecrets.LoadExisting(reconciler.Client, instance.Spec.Secrets); err != nil {
		log.Error(err, "error loading existing secrets from the Kubernetes API: %+v")
		return ctrl.Result{}, err
	}

	for _, node := range nodes {
		if err := generator.RecursivelyGenerateIfMissing(&instance.Spec, node); err != nil {
			log.Error(err, "error generating secrets: %+v")
			return ctrl.Result{}, err
		}
	}

	if instance.Spec.AppConfig.SecretsManager != v1alpha1.SecretsManagerNone {
		if err := secretsmanager.EnsureSecrets(ctx, &instance.Spec, nodes); err != nil {
			log.Error(err, "error ensuring secrets in the Secrets Manager: %+v")
			return ctrl.Result{}, err
		}
	}

	//end old main.go

	k8sSecretList := k8ssecrets.GenerateSecretAPIObjects(instance.Spec.Secrets)

	labelsForSecretAgent := func(name string) map[string]string {
		return map[string]string{"managed-by-secret-agent": "true", "secret-agent-configuration-name": name}
	}

	if instance.Spec.AppConfig.CreateKubernetesObjects {
		for _, secret := range k8sSecretList {
			// Set SecretAgentConfiguration instance as the owner and controller of the secret
			if err := ctrl.SetControllerReference(&instance, secret, reconciler.Scheme); err != nil {
				return ctrl.Result{}, err
			}
			secret.Labels = labelsForSecretAgent(instance.Name)
			k8ssecrets.ApplySecrets(reconciler.Client, []*corev1.Secret{secret})

		}
	}

	// Update the SecretAgentConfiguration status with the object names
	secretList := &corev1.SecretList{}
	listOpts := []client.ListOption{
		client.InNamespace(instance.Namespace),
		client.MatchingLabels(labelsForSecretAgent(instance.Name)),
	}
	if err := reconciler.List(ctx, secretList, listOpts...); err != nil {
		log.Error(err, "Failed to list secrets", "Namespace", instance.Namespace, "SecretAgentConfiguration", instance.Name)
		return ctrl.Result{}, err
	}
	var secretNames []string
	for _, secret := range secretList.Items {
		secretNames = append(secretNames, secret.Name)
	}
	totalManagedObjects := len(secretNames) // TODO Need to add AWS + GCP resources
	// Always Update status.k8sSecrets
	instance.Status.ManagedK8sSecrets = secretNames
	instance.Status.TotalManagedObjects = totalManagedObjects

	if err := reconciler.Status().Update(ctx, &instance); err != nil {
		log.Error(err, "Failed to update SecretAgentConfiguration status")
		return ctrl.Result{}, err
	}

	//Fix read after write in k8s api. Status updates themselves trigger a reconcile event.
	//Wait 2 seconds to allow k8s to update before triggeting another reconcile event
	time.Sleep(2 * time.Second)
	return ctrl.Result{}, nil

}

var (
	jobOwnerKey = ".metadata.controller"
	apiGVStr    = v1alpha1.GroupVersion.String()
)

//SetupWithManager is used to register the reconciler to the manager
func (reconciler *SecretAgentConfigurationReconciler) SetupWithManager(mgr ctrl.Manager) error {

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
		For(&v1alpha1.SecretAgentConfiguration{}).
		Owns(&corev1.Secret{}).
		Complete(reconciler)

}

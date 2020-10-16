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
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/time/rate"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

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
	Log                   logr.Logger
	Scheme                *runtime.Scheme
	CloudSecretsNamespace string
}

var (
	watchOwnedObjects bool = true
)

// +kubebuilder:rbac:groups=secret-agent.secrets.forgerock.io,resources=secretagentconfigurations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=secret-agent.secrets.forgerock.io,resources=secretagentconfigurations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingwebhookconfigurations;mutatingwebhookconfigurations,verbs=get;update;patch

// Reconcile reconcile loop for CRD controller
func (reconciler *SecretAgentConfigurationReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	var updatedK8sSecrets bool = false
	var rescheduleRetry bool = false
	var errorFound bool = false
	ctx := context.Background()
	log := reconciler.Log.WithValues("secretagentconfiguration", req.NamespacedName)

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
	// Stop watching for secret changes while the reconcile loop is running
	watchOwnedObjects = false
	defer func() { watchOwnedObjects = true }()
	log.V(1).Info("** Reconcile loop start **")

	if instance.Spec.AppConfig.SecretsManager != v1alpha1.SecretsManagerNone &&
		instance.Spec.AppConfig.CredentialsSecretName != "" {
		var dir string
		var cloudCredNS string

		if len(reconciler.CloudSecretsNamespace) > 0 {
			cloudCredNS = reconciler.CloudSecretsNamespace
		} else {
			cloudCredNS = instance.Namespace
		}

		// load credentials secret
		secObject, err := k8ssecrets.LoadSecret(reconciler.Client,
			instance.Spec.AppConfig.CredentialsSecretName, cloudCredNS)
		if err != nil {
			log.Error(err, "error loading cloud credentials secret from the Kubernetes API",
				"secret_name", instance.Spec.AppConfig.CredentialsSecretName,
				"namespace", cloudCredNS)
			return ctrl.Result{}, err
		}
		// Create temporary dir for gcp credentials if needed
		if instance.Spec.AppConfig.SecretsManager == v1alpha1.SecretsManagerGCP {
			dir, err := ioutil.TempDir("", "cloud_credentials-*")
			if err != nil {
				log.Error(err, "couldn't create a temporary credentials dir")
				return ctrl.Result{}, err
			}
			// clean up after ourselves
			defer os.RemoveAll(dir)
		}

		// load cloud credentials to envs and/or files
		if err := manageCloudCredentials(instance.Spec.AppConfig.SecretsManager, secObject, dir); err != nil {
			log.Error(err, "error loading cloud credentials from secret provided",
				"secret_name", instance.Spec.AppConfig.CredentialsSecretName,
				"namespace", cloudCredNS)
			return ctrl.Result{}, err
		}

	}
	// set the SAC status to inProgress only the first time around.
	if instance.Status.State == "" {
		if err := reconciler.updateStatus(ctx, &instance, true, false); err != nil {
			log.Error(err, "Failed to update status", "instance.name", instance.Name)
			return ctrl.Result{}, err
		}
	}

	for _, secretReq := range instance.Spec.Secrets {
		var k8sApplyRequired bool = false
		// load from secret k8s
		secObject, err := k8ssecrets.LoadSecret(reconciler.Client, secretReq.Name, instance.Namespace)
		if err != nil {
			log.Error(err, "error loading existing secrets from the Kubernetes API",
				"secret_name", secretReq.Name,
				"namespace", instance.Namespace)
			return ctrl.Result{}, err
		}
		log.V(1).Info("reconciling secret", "secret_name", secretReq.Name)
	secretKeys:
		for _, key := range secretReq.Keys {
			log.V(1).Info("reconciling secret key", "secret_name", secretReq.Name,
				"data_key", key.Name, "secret_type", string(key.Type))

			keyInterface, err := routeKeyInterface(secretReq.Name, key)
			if err != nil {
				log.V(0).Info("error routing secret key type",
					"secret_name", secretReq.Name,
					"data_key", key.Name,
					"secret_type", string(key.Type))
				errorFound = true
				continue secretKeys
			}
			// load from secret manager
			useSecMgr := instance.Spec.AppConfig.SecretsManager != v1alpha1.SecretsManagerNone &&
				key.Type != v1alpha1.KeyConfigTypeTrustStore
			if useSecMgr {
				log.V(1).Info("loading secret from secret-manager",
					"secret_name", secretReq.Name,
					"data_key", key.Name,
					"secret_type", string(key.Type))

				if err := keyInterface.LoadSecretFromManager(ctx, &instance.Spec.AppConfig, instance.Namespace, secretReq.Name); err != nil {
					log.Error(err, "could not load secret from manager",
						"secret_name", secretReq.Name,
						"data_key", key.Name,
						"secret_type", string(key.Type))
					rescheduleRetry, errorFound = true, true
					return ctrl.Result{Requeue: rescheduleRetry}, err
				}

			} else {
				// load from kubernetes
				log.V(1).Info("loading secret from kubernetes",
					"secret_name", secretReq.Name,
					"data_key", key.Name,
					"secret_type", string(key.Type))
				keyInterface.LoadFromData(secObject.Data)
			}
			// If the keyInterface is already in the current k8s secret, continue with the next key
			if keyInterface.InSecret(secObject) {
				log.V(1).Info("skipping secret key already found in k8s",
					"secret_name", secretReq.Name,
					"data_key", key.Name)
				continue
			}
			// Load key references and data
			keyRefSecrets := make(map[string][]byte)
			refs, refDataKeys := keyInterface.References()
			for index, ref := range refs {
				var secRefObject *corev1.Secret
				// if ref the current secret, use the values already loaded in memory, else load them from k8s
				if ref == secObject.Name {
					secRefObject = secObject
				} else {
					secRefObject, err = k8ssecrets.LoadSecret(reconciler.Client, ref, instance.Namespace)
					if err != nil {
						log.Error(err, "error looking up secret ref",
							"secret_name", secretReq.Name,
							"secret_ref", ref)
						rescheduleRetry, errorFound = true, true
					}
				}

				// if the ref is not present in k8s yet, skip this secret for now. schedule a reconcile rerun
				if len(secRefObject.Data) == 0 {
					log.V(0).Info("secret ref not found, skipping key and will retry",
						"secret_name", secretReq.Name,
						"secret_ref", ref)
					rescheduleRetry, errorFound = true, false
					break secretKeys
				}
				dataKey := fmt.Sprintf("%s/%s", ref, refDataKeys[index])
				if val, ok := secRefObject.Data[refDataKeys[index]]; ok {
					keyRefSecrets[dataKey] = val

				} else {

					log.Error(err, "secret ref data not found, skipping key",
						"secret_name", secretReq.Name,
						"secret_ref", ref,
						"secret_dataKey", dataKey)
					rescheduleRetry, errorFound = true, true
					break secretKeys
				}
			}
			if err := keyInterface.LoadReferenceData(keyRefSecrets); err != nil {
				log.Error(err, "error loading references skipping key",
					"secret_name", secretReq.Name,
					"data_key", key.Name,
					"secret_type", string(key.Type))
				rescheduleRetry, errorFound = true, true
				break secretKeys
			}

			// Generate and apply to secret manager
			if keyInterface.IsEmpty() {
				log.V(0).Info("no secret data found, generating",
					"secret_name", secretReq.Name,
					"data_key", key.Name,
					"secret_type", string(key.Type))
				err := keyInterface.Generate()
				if err != nil {
					log.Error(err, "error generating secret",
						"secret_name", secretReq.Name,
						"data_key", key.Name,
						"secret_type", string(key.Type))
					errorFound = true
					break secretKeys
				}
				if useSecMgr {
					log.V(0).Info("storing secret to secret-manager",
						"secret_name", secretReq.Name,
						"data_key", key.Name,
						"secret_type", string(key.Type))
					if err := keyInterface.EnsureSecretManager(ctx, &instance.Spec.AppConfig,
						instance.Namespace, secretReq.Name); err != nil {
						log.Error(err, "could not store secret in manager",
							"secret_name", secretReq.Name,
							"data_key", key.Name,
							"secret_type", string(key.Type))
						rescheduleRetry, errorFound = true, true
						return ctrl.Result{Requeue: rescheduleRetry}, err
					}
				}
			}
			keyInterface.ToKubernetes(secObject)
			// if we reach this point, we need to update the k8s secret with new keys
			k8sApplyRequired = true
		} // end of keys loop
		// write secret once after processing all its keys if required.
		if k8sApplyRequired {
			log.V(0).Info("applying to kubernetes",
				"secret_name", secretReq.Name)

			secObject.Labels = labelsForSecretAgent(instance.Name)
			// Set SecretAgentConfiguration instance as the owner and controller of the k8ssecret
			if err := ctrl.SetControllerReference(&instance, secObject, reconciler.Scheme); err != nil {
				return ctrl.Result{}, err
			}
			op, err := k8ssecrets.ApplySecrets(reconciler.Client, secObject)
			if err != nil {
				log.Error(err, "couldnt apply secret",
					"method", op,
					"secret_namespace", instance.Namespace,
					"secret_name", secretReq.Name)
				rescheduleRetry, errorFound = true, true
			}
			updatedK8sSecrets = true
			// Give enough time for the k8s api to update the secret to avoid race conditions
			time.Sleep(100 * time.Millisecond)
		}

		log.V(1).Info("completed reconcile for secret",
			"secret_namespace", instance.Namespace,
			"secret_name", secretReq.Name)

	} // end of secrets loop
	// Only update the instance's status if there was a k8s operation.
	// No k8s operation happen in the last reconcile loop. Update to "completed" if no updates and no errors occurred
	if updatedK8sSecrets || rescheduleRetry || errorFound {
		if err := reconciler.updateStatus(ctx, &instance, rescheduleRetry, errorFound); err != nil {
			log.Error(err, "Failed to update status", "instance.name", instance.Name)
			return ctrl.Result{}, err
		}
	}
	if rescheduleRetry {
		log.V(1).Info("Reconcile loop failed. Retry rescheduled")
	} else {
		log.Info("Reconcile loop complete",
			"secretAgentConfiguration", instance.Name)
	}
	return ctrl.Result{Requeue: rescheduleRetry}, nil
}

func labelsForSecretAgent(name string) map[string]string {
	return map[string]string{"managed-by-secret-agent": "true", "secret-agent-configuration-name": name}
}

func (reconciler *SecretAgentConfigurationReconciler) updateStatus(ctx context.Context, instance *v1alpha1.SecretAgentConfiguration, inProgress, errorFound bool) error {
	// Update the SecretAgentConfiguration status with the object names
	secretList := &corev1.SecretList{}
	listOpts := []client.ListOption{
		client.InNamespace(instance.Namespace),
		client.MatchingLabels(labelsForSecretAgent(instance.Name)),
	}
	if err := reconciler.List(ctx, secretList, listOpts...); err != nil {
		return err
	}
	var secretNames []string
	for _, secret := range secretList.Items {
		secretNames = append(secretNames, secret.Name)
	}
	totalManagedObjects := len(secretNames) // TODO Need to add AWS + GCP resources
	// Always Update status.k8sSecrets
	instance.Status.ManagedK8sSecrets = secretNames
	instance.Status.TotalManagedObjects = totalManagedObjects

	if errorFound {
		if inProgress {
			instance.Status.State = v1alpha1.SecretAgentConfigurationErrorRetry
		} else {
			instance.Status.State = v1alpha1.SecretAgentConfigurationError
		}
	} else if inProgress {
		instance.Status.State = v1alpha1.SecretAgentConfigurationInProgress
	} else {
		instance.Status.State = v1alpha1.SecretAgentConfigurationCompleted
	}

	if err := reconciler.Status().Update(ctx, instance); err != nil {
		return err
	}
	// Updating the instance will trigger a reconcile loop. This only happens at the end of the reconcile loop
	// Give enough time for the api to update
	time.Sleep(200 * time.Millisecond)
	return nil
}

func routeKeyInterface(secretName string, key *v1alpha1.KeyConfig) (generator.KeyMgr, error) {
	switch key.Type {
	case v1alpha1.KeyConfigTypeCA:
		return generator.NewRootCA(key)
	case v1alpha1.KeyConfigTypeKeyPair:
		return generator.NewCertKeyPair(key)
	case v1alpha1.KeyConfigTypePassword:
		return generator.NewPassword(key)
	case v1alpha1.KeyConfigTypeLiteral:
		return generator.NewLiteral(key)
	case v1alpha1.KeyConfigTypeSSH:
		return generator.NewSSH(key)
	case v1alpha1.KeyConfigTypeKeytool:
		return generator.NewKeyTool(key)
	case v1alpha1.KeyConfigTypeTrustStore:
		return generator.NewTrustStore(key)
	default:
		// TODO we should never hit this point once all types are implmeneted.
		// We should actually error out
		// We continue through all keys in a secret skipping unsupported types
		return nil, errors.New("Key type not implemented")
	}
}

// manageCloudCredentials handles the credential used to access the secret manager
// credentials are placed in temp files or environmental variables according to the SM specs.
func manageCloudCredentials(secManager v1alpha1.SecretsManager, secObject *corev1.Secret, dirPath string) error {

	writeFile := func(name string, contents []byte) (string, error) {
		fPath := path.Join(dirPath, name)

		// Open a new file for writing only
		file, err := os.OpenFile(
			fPath,
			os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
			0666,
		)
		if err != nil {
			return "", err
		}
		defer file.Close()

		// Write bytes to file
		_, err = file.Write(contents)
		if err != nil {
			return "", err
		}
		return fPath, nil
	}
	switch secManager {
	case v1alpha1.SecretsManagerGCP:
		keyValue, ok := secObject.Data[string(v1alpha1.SecretsManagerGoogleApplicationCredentials)]
		if !ok {
			return fmt.Errorf(fmt.Sprintf("%s must be provided in a credentials secret",
				v1alpha1.SecretsManagerGoogleApplicationCredentials))
		}
		fp, err := writeFile("gcp_credentials.json", keyValue)
		if err != nil {
			return err
		}
		if err := os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", fp); err != nil {
			return err
		}
	case v1alpha1.SecretsManagerAWS:
		if keyValue, ok := secObject.Data[string(v1alpha1.SecretsManagerAwsAccessKeyID)]; ok {
			if err := os.Setenv("AWS_ACCESS_KEY_ID", string(keyValue)); err != nil {
				return err
			}
		}
		if keyValue, ok := secObject.Data[string(v1alpha1.SecretsManagerAwsSecretAccessKey)]; ok {
			if err := os.Setenv("AWS_SECRET_ACCESS_KEY", string(keyValue)); err != nil {
				return err
			}
		}
	case v1alpha1.SecretsManagerAzure:
		// Azure managed identity - no direct credentials needed
		if keyValue, ok := secObject.Data[string(v1alpha1.SecretsManagerAzureManagedID)]; ok {
			enabled, err := strconv.ParseBool(string(keyValue))
			if err != nil {
				return err
			}
			if enabled {
				return nil
			}
		}
		if keyValue, ok := secObject.Data[string(v1alpha1.SecretsManagerAzureTenantID)]; ok {
			if err := os.Setenv("AZURE_TENANT_ID", string(keyValue)); err != nil {
				return err
			}

		}
		if keyValue, ok := secObject.Data[string(v1alpha1.SecretsManagerAzureClientID)]; ok {
			if err := os.Setenv("AZURE_CLIENT_ID", string(keyValue)); err != nil {
				return err
			}

		}
		if keyValue, ok := secObject.Data[string(v1alpha1.SecretsManagerAzureClientSecret)]; ok {
			if err := os.Setenv("AZURE_CLIENT_SECRET", string(keyValue)); err != nil {
				return err
			}
		}
	}
	return nil

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
		if !watchOwnedObjects {
			return nil
		}
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

	rateLimiter := workqueue.NewMaxOfRateLimiter(
		workqueue.NewItemExponentialFailureRateLimiter(200*time.Millisecond, 10*time.Hour),
		// 10 qps, 10 Burst
		&workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(10), 10)},
	)

	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.SecretAgentConfiguration{}).
		Owns(&corev1.Secret{}).
		WithOptions(controller.Options{RateLimiter: rateLimiter}).
		Complete(reconciler)

}

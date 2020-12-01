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
	"fmt"
	"io/ioutil"
	"os"
	"path"
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
)

// SecretAgentConfigurationReconciler reconciles a SecretAgentConfiguration object
type SecretAgentConfigurationReconciler struct {
	client.Client
	Log                   logr.Logger
	Scheme                *runtime.Scheme
	CloudSecretsNamespace string
}

// +kubebuilder:rbac:groups=secret-agent.secrets.forgerock.io,resources=secretagentconfigurations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=secret-agent.secrets.forgerock.io,resources=secretagentconfigurations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingwebhookconfigurations;mutatingwebhookconfigurations,verbs=get;update;patch

// Reconcile reconcile loop for CRD controller
func (reconciler *SecretAgentConfigurationReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	// status flags
	rescheduleRetry := false
	errorFound := false
	updateK8sSecrets := false

	ctx := context.Background()
	log := reconciler.Log.WithValues(
		"secretagentconfiguration", req.Name,
		"namespace", req.NamespacedName,
	)

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
	log.V(1).Info("** Reconcile loop start **")

	// TODO remove this and move setup of secret manager to a container
	// add conatiner to GenKeyConfig

	//	secretMgr := secretmanager.NewSecretManager(rclient, instance.AppConfig)

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
				"cloud_secret_namespace", cloudCredNS)
			return ctrl.Result{}, err
		}
		// Create temporary dir for gcp credentials if needed
		if instance.Spec.AppConfig.SecretsManager == v1alpha1.SecretsManagerGCP {
			dir, err = ioutil.TempDir("", "cloud_credentials-*")
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
				"cloud_secret_namespace", cloudCredNS)
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
		// load from secret k8s or creates a new one
		secObject, err := k8ssecrets.LoadSecret(reconciler.Client, secretReq.Name, instance.Namespace)
		// we expect secrets to be not found
		log := log.WithValues("secret_name", secretReq.Name)
		if err != nil && !k8serror.IsNotFound(err) {
			log.Error(err, "error loading existing secrets from the Kubernetes API")
			// continue and set retry, err
			rescheduleRetry, errorFound = true, true
			return ctrl.Result{}, err
		}
		// secret will either be empty or will will have data. If it has data skip.
		if len(secObject.Data) != 0 {
			// TODO this should have a check on ownership and throw a warrning if the object isn't owned by secret agent
			log.V(1).Info("secret found to have data, skipping")
			continue
		}
		log.V(1).Info("reconciling secret", "secret_name", secretReq.Name)
		gen := generator.GenConfig{
			// kubernetes secret that will have keys
			SecObject: secObject,
			// Keys that should be in secret
			KeysToGen: secretReq.Keys,
			Log:       log,
			Namespace: instance.Namespace,
			AppConfig: &instance.Spec.AppConfig,
			Client:    reconciler.Client,
			// TODO this is for secret manager refactor in the near future
			// SecretManagerClient: secretMgr,
		}
		// generate this secrets keys
		err = gen.GenKeys(ctx)
		if err != nil {
			// report err and retry
			rescheduleRetry = true
			continue
		}
		log.V(0).Info("applying to kubernetes")

		secObject.Labels = labelsForSecretAgent(instance.Name)
		// Set SecretAgentConfiguration instance as the owner and controller of the k8ssecret
		if err := ctrl.SetControllerReference(&instance, secObject, reconciler.Scheme); err != nil {
			// log error
			rescheduleRetry = true
			continue
		}
		op, err := k8ssecrets.ApplySecrets(reconciler.Client, secObject)
		if err != nil {
			log.Error(err, "couldnt apply secret",
				"method", op)
			rescheduleRetry, errorFound = true, true
			continue

		}
		updateK8sSecrets = true
	}

	// Only update the instance's status if there was a k8s operation.
	// No k8s operation happen in the last reconcile loop. Update to "completed" if no updates and no errors occurred
	if updateK8sSecrets || rescheduleRetry || errorFound {
		if err := reconciler.updateStatus(ctx, &instance, rescheduleRetry, errorFound); err != nil {
			log.Error(err, "Failed to update status")
			return ctrl.Result{}, err
		}
	}
	if rescheduleRetry {
		log.V(1).Info("Reconcile loop failed. Retry rescheduled")
	} else {
		log.Info("Reconcile loop complete")
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

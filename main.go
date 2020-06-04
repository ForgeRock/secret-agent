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

package main

import (
	"flag"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/ForgeRock/secret-agent/controllers"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	_ = clientgoscheme.AddToScheme(scheme)

	_ = v1alpha1.AddToScheme(scheme)
	// +kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	flag.StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))
	certDir := os.Getenv("CERT_DIR")
	if len(certDir) == 0 {
		certDir = "/tmp/k8s-webhook-server/serving-certs"
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr,
		Port:               9443,
		LeaderElection:     enableLeaderElection,
		LeaderElectionID:   "f8e4a0d9.secrets.forgerock.io",
		CertDir:            certDir,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err = (&controllers.SecretAgentConfigurationReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("SecretAgentConfiguration"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "SecretAgentConfiguration")
		os.Exit(1)
	}

	// Start creating certs for the webhooks
	setupLog.Info("Starting webhook related patches")

	secretName := os.Getenv("WEBHOOK_SECRET_NAME")
	namespace := os.Getenv("SERVICE_NAMESPACE")
	validatingWebhookConfigurationName := os.Getenv("VALIDATING_WEBHOOK_CONFIGURATION")
	mutatingWebhookConfigurationName := os.Getenv("MUTATING_WEBHOOK_CONFIGURATION")
	val := os.Getenv("CERTIFICATE_SANS")
	sans := strings.Split(val, ",")

	if len(secretName) == 0 || len(namespace) == 0 || len(validatingWebhookConfigurationName) == 0 ||
		len(mutatingWebhookConfigurationName) == 0 || len(sans) == 0 {
		setupLog.Error(nil, "Need ENVS: WEBHOOK_SECRET_NAME, SERVICE_NAMESPACE, "+
			"VALIDATING_WEBHOOK_CONFIGURATION, MUTATING_WEBHOOK_CONFIGURATION, CERTIFICATE_SANS")
		os.Exit(1)
	}

	rootCA, leafCert, err := controllers.GenerateCertificates(sans)
	if err != nil {
		setupLog.Error(err, "Unable to create secret")
	}

	setupLog.Info("patching webhook secret", "name", secretName)
	if err := controllers.PatchWebhookSecret(rootCA.CertPEM, leafCert.CertPEM, leafCert.PrivateKeyPEM, secretName, namespace); err != nil {
		setupLog.Error(err, "Unable to patch secret")
	}

	setupLog.Info("patching validating webhook", "name", validatingWebhookConfigurationName)
	if err := controllers.PatchValidatingWebhookConfiguration(rootCA.CertPEM, validatingWebhookConfigurationName); err != nil {
		setupLog.Error(err, "Unable to patch validating webhook")
	}

	setupLog.Info("patching mutating webhook", "name", mutatingWebhookConfigurationName)
	if err := controllers.PatchMutatingWebhookConfiguration(rootCA.CertPEM, mutatingWebhookConfigurationName); err != nil {
		setupLog.Error(err, "Unable to patch mutating webhook")
	}

	if err := os.MkdirAll(certDir, 0755); err != nil {
		setupLog.Error(err, "Unable to create certDir", "path", certDir)
	}
	if err := ioutil.WriteFile(filepath.Join(certDir, "ca.crt"), rootCA.CertPEM, 0400); err != nil {
		setupLog.Error(err, "Unable to create ca.crt")
	}
	if err := ioutil.WriteFile(filepath.Join(certDir, "tls.crt"), leafCert.CertPEM, 0400); err != nil {
		setupLog.Error(err, "Unable to create tls.crt")
	}
	if err := ioutil.WriteFile(filepath.Join(certDir, "tls.key"), leafCert.PrivateKeyPEM, 0400); err != nil {
		setupLog.Error(err, "Unable to create tls.key")
	}
	// END Create certs for the webhooks

	if err = (&v1alpha1.SecretAgentConfiguration{}).SetupWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "SecretAgentConfiguration")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

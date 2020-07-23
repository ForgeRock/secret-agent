package controllers

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/ForgeRock/secret-agent/pkg/generator"
)

var (
	webhookNamespace                   = flag.String("webhook-service-ns", "", "Namespace name of the webhook service")
	webhookServiceName                 = flag.String("webhook-service-name", "", "Service name of the webhook")
	webhookSecretName                  = flag.String("webhook-secret-name", "", "K8s secret to store/read webhook certificates")
	validatingWebhookConfigurationName = flag.String("validating-webhook-name", "", "Name of the validatingWebhookConfiguration")
	mutatingWebhookConfigurationName   = flag.String("mutating-webhook-name", "", "Name of the mutatingWebhookConfiguration")
)

// InitWebhookCertificates creates and injects req certs by the k8s webhooks
func InitWebhookCertificates(certDir string) error {

	sans := []string{
		fmt.Sprint(*webhookServiceName, ".", *webhookNamespace, ".svc"),
		fmt.Sprint(*webhookServiceName, ".", *webhookNamespace, ".svc.cluster.local"),
	}

	if len(*webhookSecretName) == 0 || len(*webhookNamespace) == 0 || len(*validatingWebhookConfigurationName) == 0 ||
		len(*mutatingWebhookConfigurationName) == 0 || len(sans) == 0 {
		return errors.New("If ENABLE_WEBHOOKS is true, must provide: " +
			"--webhook-secret-name, --webhook-service-name, --webhook-service-namespace, " +
			"--validating-webhook-name, --mutating-webhook-name")
	}

	k8sClient, err := getClient()
	if err != nil {
		return err
	}

	rootCAPem, certPEM, keyPEM, err := getWebhookSecret(k8sClient, *webhookSecretName, *webhookNamespace)
	if err != nil {
		// If we couldn't obtain the certs from the k8s secret, generate the certs and patch the k8s secret for future use
		rootCA, leafCert, err := generateCertificates(sans)
		if err != nil {
			// Unable to create secret
			return err
		}

		// Patching webhook secret
		if err := patchWebhookSecret(k8sClient, rootCA.CertPEM, leafCert.CertPEM,
			leafCert.PrivateKeyPEM, *webhookSecretName, *webhookNamespace); err != nil {
			return err
		}
		rootCAPem = rootCA.CertPEM
		certPEM = leafCert.CertPEM
		keyPEM = leafCert.PrivateKeyPEM
	}

	// Patching validating webhook
	if err := patchValidatingWebhookConfiguration(k8sClient, rootCAPem, *validatingWebhookConfigurationName); err != nil {
		return err
	}

	// Patching mutating webhook
	if err := patchMutatingWebhookConfiguration(k8sClient, rootCAPem, *mutatingWebhookConfigurationName); err != nil {
		return err
	}

	// Create certDir
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return err
	}
	// Create ca.crt
	if err := ioutil.WriteFile(filepath.Join(certDir, "ca.crt"), rootCAPem, 0400); err != nil {
		return err
	}
	// Create tls.crt
	if err := ioutil.WriteFile(filepath.Join(certDir, "tls.crt"), certPEM, 0400); err != nil {
		return err
	}
	// Create tls.key
	if err := ioutil.WriteFile(filepath.Join(certDir, "tls.key"), keyPEM, 0400); err != nil {
		return err
	}
	return nil
}

func getClient() (client.Client, error) {

	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)

	kubeconfig, err := ctrl.GetConfig()
	if err != nil {
		return nil, err
	}

	kubeclient, err := client.New(kubeconfig, client.Options{
		Scheme: scheme,
	})
	if err != nil {
		return nil, err
	}
	return kubeclient, nil
}

// generateCertificates generates the root CA and leaf certificate to be used by the webhook
func generateCertificates(sans []string) (rootCA, leafCert *generator.Certificate, err error) {
	rootCA, err = generator.GenerateRootCA("secret-agent")
	if err != nil {
		return
	}
	leafCert, err = generator.GenerateSignedCert(rootCA, v1alpha1.ECDSAWithSHA256, "", sans)
	if err != nil {
		return
	}

	return
}

// getWebhookSecret patches the named TLS secret with the TLS information
func getWebhookSecret(k client.Client, name, namespace string) (rootCAPem, certPEM, keyPEM []byte, err error) {

	k8sSecret := &corev1.Secret{}
	if err = k.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, k8sSecret); err != nil {
		return
	}
	var ok bool
	// secret found, let's grab the contents
	rootCAPem, ok = k8sSecret.Data["ca.crt"]
	if !ok {
		err = errors.New("Secret key ca.crt not found in " + name)
		return
	}
	certPEM, ok = k8sSecret.Data["tls.crt"]
	if !ok {
		err = errors.New("Secret key tls.crt not found in " + name)
		return
	}
	keyPEM, ok = k8sSecret.Data["tls.key"]
	if !ok {
		err = errors.New("Secret key tls.key not found in " + name)
		return
	}

	return
}

// patchWebhookSecret patches the named TLS secret with the TLS information
func patchWebhookSecret(k client.Client, rootCAPem, certPEM, keyPEM []byte, name, namespace string) (err error) {

	k8sSecret := &corev1.Secret{}
	if err = k.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, k8sSecret); err != nil {
		return
	}

	// secret found, we need to update
	k8sSecret.Data["ca.crt"] = rootCAPem
	k8sSecret.Data["tls.crt"] = certPEM
	k8sSecret.Data["tls.key"] = keyPEM

	err = k.Update(context.TODO(), k8sSecret)

	return
}

// patchValidatingWebhookConfiguration patches the given ValidatingWebhookConfiguration with the caBuncle
func patchValidatingWebhookConfiguration(k client.Client, rootCAPem []byte, name string) (err error) {

	webhookConfiguration := &admissionregistrationv1beta1.ValidatingWebhookConfiguration{}
	if err = k.Get(context.TODO(), types.NamespacedName{Name: name}, webhookConfiguration); err != nil {
		return
	}
	for i := range webhookConfiguration.Webhooks {
		webhookConfiguration.Webhooks[i].ClientConfig.CABundle = rootCAPem
	}

	err = k.Update(context.TODO(), webhookConfiguration)

	return
}

// patchMutatingWebhookConfiguration patches the given MutatingWebhookConfiguration with the caBuncle
func patchMutatingWebhookConfiguration(k client.Client, rootCAPem []byte, name string) (err error) {

	webhookConfiguration := &admissionregistrationv1beta1.MutatingWebhookConfiguration{}
	if err = k.Get(context.TODO(), types.NamespacedName{Name: name}, webhookConfiguration); err != nil {
		return
	}
	for i := range webhookConfiguration.Webhooks {
		webhookConfiguration.Webhooks[i].ClientConfig.CABundle = rootCAPem
	}
	err = k.Update(context.TODO(), webhookConfiguration)

	return

}

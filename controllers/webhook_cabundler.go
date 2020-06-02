package controllers

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/ForgeRock/secret-agent/pkg/generator"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type k8s struct {
	clientset kubernetes.Interface
}

// InitWebhookCertificates creates and injects req certs by the k8s webhooks
func InitWebhookCertificates(certDir string) error {

	secretName := os.Getenv("WEBHOOK_SECRET_NAME")
	namespace := os.Getenv("SERVICE_NAMESPACE")
	validatingWebhookConfigurationName := os.Getenv("VALIDATING_WEBHOOK_CONFIGURATION")
	mutatingWebhookConfigurationName := os.Getenv("MUTATING_WEBHOOK_CONFIGURATION")
	val := os.Getenv("CERTIFICATE_SANS")
	sans := strings.Split(val, ",")

	if len(secretName) == 0 || len(namespace) == 0 || len(validatingWebhookConfigurationName) == 0 ||
		len(mutatingWebhookConfigurationName) == 0 || len(sans) == 0 {
		return errors.New("Need ENVS: WEBHOOK_SECRET_NAME, SERVICE_NAMESPACE, " +
			"VALIDATING_WEBHOOK_CONFIGURATION, MUTATING_WEBHOOK_CONFIGURATION, CERTIFICATE_SANS")
	}

	rootCA, leafCert, err := generateCertificates(sans)
	if err != nil {
		// Unable to create secret
		return err
	}

	// Patching webhook secret
	if err := patchWebhookSecret(rootCA.CertPEM, leafCert.CertPEM, leafCert.PrivateKeyPEM, secretName, namespace); err != nil {
		return err
	}

	// Patching validating webhook
	if err := patchValidatingWebhookConfiguration(rootCA.CertPEM, validatingWebhookConfigurationName); err != nil {
		return err
	}

	// Patching mutating webhook
	if err := patchMutatingWebhookConfiguration(rootCA.CertPEM, mutatingWebhookConfigurationName); err != nil {
		return err
	}

	// Unable to create certDir
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return err
	}
	// Unable to create ca.crt
	if err := ioutil.WriteFile(filepath.Join(certDir, "ca.crt"), rootCA.CertPEM, 0400); err != nil {
		return err
	}
	// Unable to create tls.crt
	if err := ioutil.WriteFile(filepath.Join(certDir, "tls.crt"), leafCert.CertPEM, 0400); err != nil {
		return err
	}
	// Unable to create tls.key
	if err := ioutil.WriteFile(filepath.Join(certDir, "tls.key"), leafCert.PrivateKeyPEM, 0400); err != nil {
		return err
	}
	return nil
}

func getClientSet(kubeconfig string) (*k8s, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}

	c, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &k8s{clientset: c}, nil
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

// patchWebhookSecret patches the named TLS secret with the TLS information
func patchWebhookSecret(rootCAPem, certPEM, keyPEM []byte, name, namespace string) (err error) {
	k, err := getClientSet("")
	if err != nil {
		return
	}
	k8sSecret, err := k.clientset.CoreV1().Secrets(namespace).Get(name, metav1.GetOptions{})
	if err != nil {
		return
	}

	// secret found, we need to update
	k8sSecret.Data["ca.crt"] = rootCAPem
	k8sSecret.Data["tls.crt"] = certPEM
	k8sSecret.Data["tls.key"] = keyPEM
	_, err = k.clientset.CoreV1().Secrets(namespace).Update(k8sSecret)
	if err != nil {
		return
	}

	return
}

// patchValidatingWebhookConfiguration patches the given ValidatingWebhookConfiguration with the caBuncle
func patchValidatingWebhookConfiguration(rootCAPem []byte, name string) (err error) {
	k, err := getClientSet("")
	if err != nil {
		return
	}
	webhookConfiguration, err := k.clientset.
		AdmissionregistrationV1beta1().
		ValidatingWebhookConfigurations().
		Get(name, metav1.GetOptions{})
	if err != nil {
		return
	}
	for i := range webhookConfiguration.Webhooks {
		h := &webhookConfiguration.Webhooks[i]
		h.ClientConfig.CABundle = rootCAPem
	}
	_, err = k.clientset.AdmissionregistrationV1beta1().ValidatingWebhookConfigurations().Update(webhookConfiguration)

	return
}

// patchMutatingWebhookConfiguration patches the given MutatingWebhookConfiguration with the caBuncle
func patchMutatingWebhookConfiguration(rootCAPem []byte, name string) (err error) {
	k, err := getClientSet("")
	if err != nil {
		return
	}
	webhookConfiguration, err := k.clientset.
		AdmissionregistrationV1beta1().
		MutatingWebhookConfigurations().
		Get(name, metav1.GetOptions{})
	if err != nil {
		return
	}
	for i := range webhookConfiguration.Webhooks {
		h := &webhookConfiguration.Webhooks[i]
		h.ClientConfig.CABundle = rootCAPem
	}
	_, err = k.clientset.AdmissionregistrationV1beta1().MutatingWebhookConfigurations().Update(webhookConfiguration)

	return

}

package controllers

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/ForgeRock/secret-agent/pkg/generator"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type k8s struct {
	clientset kubernetes.Interface
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

// GenerateCertificates generates the root CA and leaf certificate to be used by the webhook
func GenerateCertificates(sans []string) (rootCA, leafCert generator.Certificate, err error) {
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

// PatchWebhookSecret patches the named TLS secret with the TLS information
func PatchWebhookSecret(rootCAPem, certPEM, keyPEM []byte, name string, namespace string) (err error) {
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

// PatchValidatingWebhookConfiguration patches the given ValidatingWebhookConfiguration with the caBuncle
func PatchValidatingWebhookConfiguration(rootCAPem []byte, name string) (err error) {
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

// PatchMutatingWebhookConfiguration patches the given MutatingWebhookConfiguration with the caBuncle
func PatchMutatingWebhookConfiguration(rootCAPem []byte, name string) (err error) {
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

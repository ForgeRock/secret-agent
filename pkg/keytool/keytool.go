package keytool

import (
	"fmt"
	"io/ioutil"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	// "os/exec"
	// "github.com/ForgeRock/secret-agent/pkg/memorystore"
	// "github.com/pkg/errors"
)

const (
	dsKeyMgrPath = "/opt/gen/opendj/bin/dskeymgr"
	keytoolPath  = "/usr/local/openjdk-11/bin/keytool"
)

var (
	tempDir          = ""
	keystoreFilePath = ""
)

func init() {
	dir, err := ioutil.TempDir("", "secrets")
	if err != nil {
		panic(err)
	}
	tempDir = dir

	keystoreFilePath = fmt.Sprintf("%s/keystore.p12", tempDir)
}

// GenerateKeyPair generates a keystore
func GenerateKeyPair(node *v1alpha1.Node) ([]byte, error) {
	// // fetch the keystore password
	// keystorePassword := ""
	// for _, parentNode := range node.Parents {
	//     if memorystore.Equal(parentNode.Path, node.KeyConfig.StorePassPath) {
	//         keystorePassword = string(parentNode.Value)
	//         break
	//     }
	// }
	// if len(keystorePassword) == 0 {
	//     return []byte{}, errors.WithStack(errors.New("Expected password length to be non-zero"))
	// }

	// // fetch the deployment key
	// deploymentKeyNode := &v1alpha1.Node{}
	// found := false
	// for _, parentNode := range node.Parents {
	//     if memorystore.Equal(parentNode.Path, node.AliasConfig.SignedWithPath) {
	//         deploymentKeyNode = parentNode
	//         found = true
	//         break
	//     }
	// }
	// if !found {
	//     return []byte{}, errors.WithStack(errors.New("Expected to find deployment key in parent nodes"))
	// }

	// // create the deployment key CA
	// // opendj/bin/dskeymgr create-tls-key-pair -k secretvalue -w secretvalue -K secrets/generic/am-https/keystore.p12 -W secretvalue -a ssl-key-pair -h openam -s CN=am
	// cmd := exec.Command(
	//     dsKeyMgrPath, "create-tls-key-pair",
	//     "--deploymentKey", string(deploymentKeyNode.Value),
	//     "--deploymentKeyPassword", deploymentKeyPassword,
	//     "--keyStoreFile", keystoreFilePath,
	//     "--keyStorePassword", keystorePassword, // storepass, not keypass
	//     "--alias", node.AliasConfig.Alias,
	//     "--hostname", TODO,
	//     "--subjectDn", fmt.Sprintf("CN=%s", node.AliasConfig.CommonName),
	// )
	// stdoutStderr, err := cmd.CombinedOutput()
	// if err != nil {
	//     return []byte{}, err
	// }

	// // keytool -genkeypair -alias es256test -dname CN=es256test,O=ForgeRock,L=Bristol,ST=Bristol,C=UK -keyalg EC -keysize 256 -sigalg SHA256withECDSA --validity 3650 -keystore secrets/generic/am-runtime-keystore/keystore-runtime.jceks -storetype jceks -storepass secretValue -keypass secretValue
	// cmd = exec.Command(
	//     keytoolPath, "-genkeypair",
	//     "-alias", "es256test",
	//     "-dname", "CN=es256test,O=ForgeRock,L=Bristol,ST=Bristol,C=UK",
	//     "-keyalg", "EC",
	//     "-keysize", "256",
	//     "-sigalg", "SHA256withECDSA",
	//     "--validity", "3650",
	//     "-keystore", "secrets/generic/am-runtime-keystore/keystore-runtime.jceks",
	//     "-storetype", "jceks",
	//     "-storepass", "secretValue",
	//     "-keypass", "secretValue",
	// )
	// stdoutStderr, err := cmd.CombinedOutput()
	// if err != nil {
	//     return []byte{}, err
	// }

	return []byte{}, nil
}

package memorystore

import (
	secretagentv1alpha1 "github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/pkg/errors"
)

// EnsureAcyclic ensures the defined dependencies are acycilic,
//   meaning there are no cirular dependencies
func EnsureAcyclic(nodes []*secretagentv1alpha1.Node) error {
	// has no nodes, is acyclic
	if len(nodes) == 0 {
		return nil
	}

	// has no leaf, is cyclic
	//   a leaf is a node with no parents
	foundCount := 0
	for _, node := range nodes {
		if len(node.Parents) == 0 {
			foundCount++
		}
	}
	if foundCount == 0 {
		return errors.WithStack(errors.New("There are circular dependencies in the config, cannot generate"))
	}

	// remove a leaf
	for index, node := range nodes {
		if len(node.Parents) == 0 {
			// remove node from nodes
			nodes[index] = nodes[len(nodes)-1] // copy last node to index
			nodes[len(nodes)-1] = nil          // set last node to nil
			nodes = nodes[:len(nodes)-1]       // truncate
			// remove node from all other nodes' list of parents
			for _, n := range nodes {
				for parentIndex, parentNode := range n.Parents {
					if node == parentNode {
						n.Parents[parentIndex] = n.Parents[len(n.Parents)-1]
						n.Parents[len(n.Parents)-1] = nil
						n.Parents = n.Parents[:len(n.Parents)-1]
					}
				}
			}
			break // break loop since nodes slice has changed
		}
	}

	return EnsureAcyclic(nodes)
}

// GetDependencyNodes generates the dependency tree(s)
func GetDependencyNodes(config *secretagentv1alpha1.SecretAgentConfigurationSpec) []*secretagentv1alpha1.Node {
	nodes := []*secretagentv1alpha1.Node{}
	// create nodes without parents or children
	nodes = rangeOverSecrets(config.Secrets, nodes, createNode)

	// now set parents and children
	nodes = rangeOverSecrets(config.Secrets, nodes, addParentsAndChildren)

	return nodes
}

// rangeFunc is a function to be run for each path
type rangeFunc func([]string, []string, *secretagentv1alpha1.SecretConfig, *secretagentv1alpha1.KeyConfig, *secretagentv1alpha1.AliasConfig, []*secretagentv1alpha1.Node) []*secretagentv1alpha1.Node

// rangeOverSecrets ranges over the secrets and runs functions to create and update dependency nodes
func rangeOverSecrets(secretsConfig []*secretagentv1alpha1.SecretConfig, nodes []*secretagentv1alpha1.Node, fn rangeFunc) []*secretagentv1alpha1.Node {
	for _, secretConfig := range secretsConfig {
		for _, keyConfig := range secretConfig.Keys {
			// key privateKeyPath
			nodes = fn(keyConfig.PrivateKeyPath, []string{secretConfig.Name, keyConfig.Name}, secretConfig, keyConfig, nil, nodes)
			// key storePassPath
			nodes = fn(keyConfig.StorePassPath, []string{secretConfig.Name, keyConfig.Name}, secretConfig, keyConfig, nil, nodes)
			// key keyPassPath
			nodes = fn(keyConfig.KeyPassPath, []string{secretConfig.Name, keyConfig.Name}, secretConfig, keyConfig, nil, nodes)
			for _, aliasConfig := range keyConfig.AliasConfigs {
				// key alias signedWithPath
				nodes = fn(aliasConfig.SignedWithPath, []string{secretConfig.Name, keyConfig.Name, aliasConfig.Alias}, secretConfig, keyConfig, aliasConfig, nodes)
				// key passwordPath
				nodes = fn(aliasConfig.PasswordPath, []string{secretConfig.Name, keyConfig.Name, aliasConfig.Alias}, secretConfig, keyConfig, aliasConfig, nodes)
			}
		}
	}

	return nodes
}

// createNode is a rangeFunc that creates dependency nodes without parents or children
func createNode(parent, path []string, secretConfig *secretagentv1alpha1.SecretConfig, keyConfig *secretagentv1alpha1.KeyConfig, aliasConfig *secretagentv1alpha1.AliasConfig, nodes []*secretagentv1alpha1.Node) []*secretagentv1alpha1.Node {
	// make sure it doesn't already exist
	for _, node := range nodes {
		if Equal(node.Path, path) {
			return nodes
		}
	}
	node := &secretagentv1alpha1.Node{
		Path:         path,
		SecretConfig: secretConfig,
		KeyConfig:    keyConfig,
		AliasConfig:  aliasConfig,
	}
	nodes = append(nodes, node)
	switch len(path) {
	case 2:
		keyConfig.Node = node
	case 3:
		aliasConfig.Node = node
	default:
		panic("Length of path is not 2 or 3!")
	}

	return nodes
}

// addParentsAndChildren is a rangeFunc that sets the parents and children for dependency nodes
func addParentsAndChildren(parentPath, path []string, secretConfig *secretagentv1alpha1.SecretConfig, keyConfig *secretagentv1alpha1.KeyConfig, aliasConfig *secretagentv1alpha1.AliasConfig, nodes []*secretagentv1alpha1.Node) []*secretagentv1alpha1.Node {
	if len(parentPath) > 0 {
		// find the parent node(s) of the path
	parentNodes:
		for _, parentNode := range nodes {
			if Equal(parentNode.Path, parentPath) {
				node := &secretagentv1alpha1.Node{}
				if aliasConfig != nil {
					node = aliasConfig.Node
				} else {
					node = keyConfig.Node
				}
				// make sure it doesn't already exist in parents
				for _, n := range node.Parents {
					if Equal(n.Path, parentNode.Path) {
						continue parentNodes
					}
				}
				// add the parents and children
				node.Parents = append(node.Parents, parentNode)
				parentNode.Children = append(parentNode.Children, node)
				break
			}
		}
	}

	// all aliases should be parents of the relevant secret key
	if keyConfig.Type == secretagentv1alpha1.TypePKCS12 && aliasConfig != nil {
		// make sure it doesn't already exist
		alreadyExists := false
		for _, parentNode := range keyConfig.Node.Parents {
			if Equal(parentNode.Path, aliasConfig.Node.Path) {
				alreadyExists = true
			}
		}
		if !alreadyExists {
			// add the parents and children
			keyConfig.Node.Parents = append(keyConfig.Node.Parents, aliasConfig.Node)
			aliasConfig.Node.Children = append(aliasConfig.Node.Children, keyConfig.Node)
		}
	}

	// storePassPath and keyPassPath should be parents of all aliases
	if keyConfig.Type == secretagentv1alpha1.TypePKCS12 && aliasConfig != nil {
		// find keyPassPath node
		keyPassNode := &secretagentv1alpha1.Node{}
		for _, n := range nodes {
			if Equal(n.Path, keyConfig.KeyPassPath) {
				keyPassNode = n
				break
			}
		}
		// make sure it doesn't already exist
		alreadyExists := false
		for _, parentNode := range aliasConfig.Node.Parents {
			if Equal(parentNode.Path, keyPassNode.Path) {
				alreadyExists = true
			}
		}
		if !alreadyExists {
			aliasConfig.Node.Parents = append(aliasConfig.Node.Parents, keyPassNode)
			keyPassNode.Children = append(keyPassNode.Children, aliasConfig.Node)
		}
		// find storePassPath node
		storePassNode := &secretagentv1alpha1.Node{}
		for _, n := range nodes {
			if Equal(n.Path, keyConfig.StorePassPath) {
				storePassNode = n
				break
			}
		}
		// make sure it doesn't already exist
		alreadyExists = false
		for _, parentNode := range aliasConfig.Node.Parents {
			if Equal(parentNode.Path, storePassNode.Path) {
				alreadyExists = true
			}
		}
		if !alreadyExists {
			aliasConfig.Node.Parents = append(aliasConfig.Node.Parents, storePassNode)
			storePassNode.Children = append(storePassNode.Children, aliasConfig.Node)
		}
	}

	return nodes
}

// Equal checks slice equality
func Equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for index, value := range a {
		if value != b[index] {
			return false
		}
	}

	return true
}

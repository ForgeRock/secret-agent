package memorystore

import (
	"fmt"
	"reflect"
	"sort"
	"testing"

	secretagentv1alpha1 "github.com/ForgeRock/secret-agent/api/v1alpha1"
	memorystore_test "github.com/ForgeRock/secret-agent/pkg/memorystore/test"
)

func TestEnsureAcyclic(t *testing.T) {
	nodes, _ := memorystore_test.GetExpectedNodesConfiguration2()
	err := EnsureAcyclic(nodes)
	if err != nil {
		t.Errorf("Expected no error, got \n%s", err)
	}

	// create circular dependency
	nodes, _ = memorystore_test.GetExpectedNodesConfiguration2()
	// find the secretAkeyA node
	secretAkeyA := &secretagentv1alpha1.Node{}
	for _, node := range nodes {
		if Equal(node.Path, []string{"SecretA", "KeyA"}) {
			secretAkeyA = node
		}
	}
	// find the secretCkeyCalias1 node and make it depend on secretAkeyA
	//   secretAkeyA already depends on secretCkeyCalias1 through secretBkeyB
	for _, node := range nodes {
		if Equal(node.Path, []string{"SecretC", "KeyC", "Alias1"}) {
			node.Parents = append(node.Parents, secretAkeyA)
		}
	}
	err = EnsureAcyclic(nodes)
	if err == nil {
		t.Error("Expected error, got none")
	}
}

func TestGetDependencyNodes(t *testing.T) {
	// configuration 1
	expectedNodes, config := memorystore_test.GetExpectedNodesConfiguration1()
	expectedNodes = sortParentsAndChildren(expectedNodes)
	nodes := sortParentsAndChildren(GetDependencyNodes(config))
	if !reflect.DeepEqual(nodes, expectedNodes) {
		expectedN := ""
		for _, s := range expectedNodes {
			expectedN = fmt.Sprintf("%v\n%p: %v", expectedN, s, s)
		}
		gotN := ""
		for _, s := range nodes {
			gotN = fmt.Sprintf("%v\n%p: %v", gotN, s, s)
		}
		t.Errorf("Expected \n%s, got \n%s", expectedN, gotN)
	}

	// configuration 2
	expectedNodes, config = memorystore_test.GetExpectedNodesConfiguration2()
	expectedNodes = sortParentsAndChildren(expectedNodes)
	nodes = sortParentsAndChildren(GetDependencyNodes(config))
	if !reflect.DeepEqual(nodes, expectedNodes) {
		expectedN := ""
		for _, s := range expectedNodes {
			expectedN = fmt.Sprintf("%v\n%p: %v", expectedN, s, s)
		}
		gotN := ""
		for _, s := range nodes {
			gotN = fmt.Sprintf("%v\n%p: %v", gotN, s, s)
		}
		t.Errorf("Expected \n%s, got \n%s", expectedN, gotN)
	}
}

func TestEqual(t *testing.T) {
	asdf := []string{"asdf", "fdsa"}
	tyui := []string{"tyui", "iuyt"}
	asdf2 := []string{"asdf", "fdsa"}
	asdf3 := []string{"asdf", "fdsa", "asdf"}

	truthy := Equal(asdf, tyui)
	if truthy {
		t.Errorf("Expected false, got %t", truthy)
	}
	truthy = Equal(asdf, asdf2)
	if !truthy {
		t.Errorf("Expected true, got %t", truthy)
	}
	truthy = Equal(asdf, asdf3)
	if truthy {
		t.Errorf("Expected false, got %t", truthy)
	}
}

type nodeSorter []*secretagentv1alpha1.Node

func (nodes nodeSorter) Len() int {
	return len(nodes)
}

func (nodes nodeSorter) Swap(i, j int) {
	nodes[i], nodes[j] = nodes[j], nodes[i]
}

func (nodes nodeSorter) Less(i, j int) bool {
	return fmt.Sprintf("%p", nodes[i]) < fmt.Sprintf("%p", nodes[j])
}

func sortParentsAndChildren(nodes []*secretagentv1alpha1.Node) []*secretagentv1alpha1.Node {
	for _, node := range nodes {
		sort.Sort(nodeSorter(node.Parents))
		sort.Sort(nodeSorter(node.Children))
	}

	return nodes
}

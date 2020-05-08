package memorystore

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/ForgeRock/secret-agent/pkg/memorystore/test"
	"github.com/ForgeRock/secret-agent/pkg/types"
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
	secretAkeyA := &types.Node{}
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
	// setup
	expectedNodes, config := memorystore_test.GetExpectedNodesConfiguration1()

	// test
	nodes := GetDependencyNodes(config)
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

	// setup
	expectedNodes, config = memorystore_test.GetExpectedNodesConfiguration2()

	// test
	nodes = GetDependencyNodes(config)
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

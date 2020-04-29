package memorystore

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/ForgeRock/secret-agent/pkg/memorystore/test"
)

func TestGetDependencyNodes(t *testing.T) {
	// setup
	expectedNodes, config := memorystore_test.GetExpectedNodesConfiguration1()

	// test
	nodes := GetDependencyNodes(config)
	if !reflect.DeepEqual(nodes, expectedNodes) {
		expectedN := ""
		for _, s := range expectedNodes {
			expectedN = fmt.Sprintf("%v\n%v", expectedN, s)
		}
		gotN := ""
		for _, s := range nodes {
			gotN = fmt.Sprintf("%v\n%v", gotN, s)
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
			expectedN = fmt.Sprintf("%v\n%v", expectedN, s)
		}
		gotN := ""
		for _, s := range nodes {
			gotN = fmt.Sprintf("%v\n%v", gotN, s)
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

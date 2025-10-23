package main

import (
	"fmt"
	"log"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	arangoadapter "github.com/denisbytes/arango-adapter"
)

func main() {
	// Example showing connection to an ArangoDB cluster with multiple coordinators
	// The adapter will use round-robin load balancing between endpoints

	adapter, err := arangoadapter.NewAdapter(
		arangoadapter.WithEndpoints(
			"http://coordinator1:8529",
			"http://coordinator2:8529",
			"http://coordinator3:8529",
		),
		arangoadapter.WithAuthentication("root", "password"),
		arangoadapter.WithDatabase("casbin"),
		arangoadapter.WithCollection("casbin_rule"),
	)
	if err != nil {
		log.Fatalf("Failed to create adapter: %v", err)
	}

	// Define a simple RBAC model
	modelText := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`

	m, err := model.NewModelFromString(modelText)
	if err != nil {
		log.Fatalf("Failed to create model: %v", err)
	}

	// Create the enforcer
	e, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		log.Fatalf("Failed to create enforcer: %v", err)
	}

	// Add some policies
	fmt.Println("Adding policies...")
	e.AddPolicy("alice", "data1", "read")
	e.AddPolicy("bob", "data2", "write")
	e.AddGroupingPolicy("alice", "admin")

	// Save to ArangoDB cluster
	if err := e.SavePolicy(); err != nil {
		log.Fatalf("Failed to save policy: %v", err)
	}

	// Test permissions
	fmt.Println("\nTesting permissions:")
	if allowed, _ := e.Enforce("alice", "data1", "read"); allowed {
		fmt.Println("✓ Alice can read data1")
	}

	fmt.Println("Successfully connected to ArangoDB cluster and saved policies!")
}

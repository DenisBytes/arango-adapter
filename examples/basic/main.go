package main

import (
	"fmt"
	"log"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	arangoadapter "github.com/denisbytes/arango-adapter"
)

func main() {
	// Create the adapter using the new options pattern
	// Make sure you have ArangoDB running on localhost:8529
	// You can start one with: docker run -e ARANGO_ROOT_PASSWORD=password -p 8529:8529 arangodb/arangodb:latest

	adapter, err := arangoadapter.NewAdapter(
		arangoadapter.WithEndpoints("http://localhost:8529"),
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
	e.AddPolicy("data_admin", "data1", "read")
	e.AddPolicy("data_admin", "data1", "write")
	e.AddPolicy("data_admin", "data2", "read")
	e.AddPolicy("data_admin", "data2", "write")

	// Add some role assignments
	e.AddGroupingPolicy("alice", "data_admin")

	// Save everything to the database
	fmt.Println("Saving policies to ArangoDB...")
	if err := e.SavePolicy(); err != nil {
		log.Fatalf("Failed to save policy: %v", err)
	}

	// Test some permissions
	fmt.Println("\nTesting permissions:")

	testCases := []struct {
		sub string
		obj string
		act string
	}{
		{"alice", "data1", "read"},
		{"alice", "data1", "write"},
		{"alice", "data2", "read"},
		{"bob", "data1", "read"},
		{"bob", "data2", "write"},
	}

	for _, tc := range testCases {
		allowed, err := e.Enforce(tc.sub, tc.obj, tc.act)
		if err != nil {
			log.Printf("Error enforcing: %v", err)
			continue
		}
		status := "✗ DENIED"
		if allowed {
			status = "✓ ALLOWED"
		}
		fmt.Printf("%s: %s can %s %s\n", status, tc.sub, tc.act, tc.obj)
	}

	// Show all policies
	fmt.Println("\nAll policies in database:")
	policies, _ := e.GetPolicy()
	for _, p := range policies {
		fmt.Printf("  %v\n", p)
	}

	fmt.Println("\nAll role assignments:")
	roles, _ := e.GetGroupingPolicy()
	for _, r := range roles {
		fmt.Printf("  %s has role %s\n", r[0], r[1])
	}

	fmt.Println("\nDone! Check your ArangoDB at http://localhost:8529")
}

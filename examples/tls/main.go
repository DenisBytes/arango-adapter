package main

import (
	"fmt"
	"log"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	arangoadapter "github.com/denisbytes/arango-adapter"
)

func main() {
	// Example showing TLS connection to ArangoDB
	// This assumes you have a TLS-enabled ArangoDB cluster running

	adapter, err := arangoadapter.NewAdapter(
		arangoadapter.WithEndpoints("https://localhost:8529"),
		arangoadapter.WithAuthentication("root", "password"),
		arangoadapter.WithDatabase("casbin"),
		arangoadapter.WithCollection("casbin_rule"),
		arangoadapter.WithTLS("/path/to/ca-cert.pem"), // Path to your CA certificate
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

	// Save to ArangoDB
	if err := e.SavePolicy(); err != nil {
		log.Fatalf("Failed to save policy: %v", err)
	}

	fmt.Println("Successfully connected to ArangoDB with TLS and saved policies!")
}

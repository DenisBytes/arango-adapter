# arango-adapter

An ArangoDB adapter for [Casbin](https://casbin.org/), a powerful and efficient access control library in Go.

## Features
- Supports ArangoDB as a backend for Casbin policies.
- Implements Casbin's `persist.Adapter` and `persist.BatchAdapter` interfaces.
- Provides seamless integration with Casbin's policy management.

## Installation

```sh
go get github.com/DenisBytes/arango-adapter
```

## Usage

```go
package main

import (
	"log"

	"github.com/casbin/casbin/v2"
  "arangoadapter "github.com/DenisBytes/arango-adapter"
)

func main() {
	// Initialize the adapter with ArangoDB connection details
  endpoints := []string{"http:localhost:8529"}
  endpoint := connection.NewRoundRobinEndpoints(endpoints)
  conn = connection.NewHttp2Connection(connection.DefaultHTTP2ConfigurationWrapper(endpoint, true))
  client := arangodb.NewClient(conn)
  
  a, err := arangoadapter.NewAdapter(client, "db_name", "collection_name  ")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize adapter: %v", err)
	}

 	modelPath := filepath.Join("config", "rbac_model.conf")
	policyPath := filepath.Join("config", "rbac_policy.csv")

	// Create a Casbin enforcer with the adapter
	enforcer, err := casbin.NewEnforcer(modelPath, policyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create enforcer: %v", err)
	}

	err = enforcer.InitWithFile(modelPath, policyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to init enforcer: %v", err)
	}

	err = a.SavePolicy(enforcer.GetModel())
	if err != nil {
		return nil, fmt.Errorf("failed to save policy: %v", err)
	}

	// Load policies from ArangoDB
	if err := enforcer.LoadPolicy(); err != nil {
		ci.logger.Warnw("Failed to load initial policy", "error", err)
	}

	enforcer.EnableAutoSave(true)

	// Check permissions
	allowed, err := enforcer.Enforce("alice", "data1", "read")
	if err != nil {
		log.Fatalf("Error during enforcement: %v", err)
	}

	if allowed {
		log.Println("Access granted")
	} else {
		log.Println("Access denied")
	}
}
```


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contribution

Pull requests are welcome! Please open an issue first to discuss any major changes.

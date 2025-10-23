# Examples

This directory contains example code showing how to use the ArangoDB adapter for Casbin.

## Available Examples

### 1. Basic Usage (`basic/`)

The fundamental usage pattern with the new options API:

- Simple RBAC model
- Adding policies and role assignments
- Testing permissions
- Saving and loading from the database

```bash
cd basic && go run main.go
```

### 2. TLS Configuration (`tls/`)

Shows how to connect to ArangoDB with TLS enabled:

- Secure HTTPS connections
- CA certificate configuration
- Custom TLS settings

```bash
cd tls && go run main.go
```

### 3. Cluster Setup (`cluster/`)

Demonstrates connecting to an ArangoDB cluster:

- Multiple coordinator endpoints
- Round-robin load balancing
- High availability setup

```bash
cd cluster && go run main.go
```

## Prerequisites

All examples require a running ArangoDB instance. The easiest way to get started:

```bash
docker run -e ARANGO_ROOT_PASSWORD=password -p 8529:8529 arangodb/arangodb:latest
```

Access the web UI at http://localhost:8529 with:
- Username: `root`
- Password: `password`

## What to Try Next

1. Modify the model to add more complex rules
2. Try different matchers (regex, wildcards, ABAC, etc.)
3. Experiment with multiple role hierarchies
4. Add more policies dynamically
5. Try the filtered policy removal functions
6. Set up a multi-node ArangoDB cluster

Check out the [Casbin documentation](https://casbin.org/docs/overview) for more ideas on what you can build!

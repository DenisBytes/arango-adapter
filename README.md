# ArangoDB Adapter for Casbin

A persistent adapter for [Casbin](https://github.com/casbin/casbin) that uses [ArangoDB](https://www.arangodb.com/) as the storage backend. Store your authorization policies in ArangoDB instead of flat files, with support for clusters, TLS, and flexible configuration.

## Why ArangoDB?

ArangoDB is a multi-model database that excels at storing graph data, documents, and key-value pairs. If you're already using ArangoDB or need the flexibility it provides, this adapter makes it easy to persist Casbin policies there.

## Features

- ✅ **Simple configuration** - Functional options pattern for easy setup
- ✅ **TLS support** - Secure connections with custom certificate configuration
- ✅ **Cluster support** - Multiple endpoints with round-robin load balancing
- ✅ **Auto-creation** - Automatically creates database and collection if they don't exist
- ✅ **Thread-safe** - Safe for concurrent use
- ✅ **Context-aware** - All major operations support context for timeouts and cancellation
- ✅ **Backward compatible** - Still supports direct client usage if needed

## Installation

```bash
go get github.com/denisbytes/arango-adapter
```

## Quick Start

```go
package main

import (
    "log"

    arangoadapter "github.com/denisbytes/arango-adapter"
    "github.com/casbin/casbin/v2"
)

func main() {
    // Create adapter with simple configuration
    adapter, err := arangoadapter.NewAdapter(
        arangoadapter.WithEndpoints("http://localhost:8529"),
        arangoadapter.WithAuthentication("root", "password"),
        arangoadapter.WithDatabase("casbin"),
        arangoadapter.WithCollection("casbin_rule"),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Create the enforcer
    enforcer, err := casbin.NewEnforcer("model.conf", adapter)
    if err != nil {
        log.Fatal(err)
    }

    // Use Casbin as normal
    enforcer.AddPolicy("alice", "data1", "read")
    enforcer.SavePolicy()
}
```

## Configuration Options

The adapter uses the functional options pattern for flexible configuration:

### Basic Options

```go
// Set ArangoDB endpoints (single server or cluster)
WithEndpoints("http://localhost:8529")

// Set authentication
WithAuthentication("username", "password")

// Set database name (default: "casbin")
WithDatabase("my_database")

// Set collection name (default: "casbin_rule")
WithCollection("my_collection")
```

### TLS Configuration

```go
// Enable TLS with a CA certificate file
adapter, err := arangoadapter.NewAdapter(
    arangoadapter.WithEndpoints("https://localhost:8529"),
    arangoadapter.WithAuthentication("root", "password"),
    arangoadapter.WithTLS("/path/to/ca-cert.pem"),
)
```

Or use a custom TLS configuration:

```go
import (
    "crypto/tls"
    "crypto/x509"
    "os"
)

// Load your certificates
caCert, _ := os.ReadFile("/path/to/ca-cert.pem")
caCertPool := x509.NewCertPool()
caCertPool.AppendCertsFromPEM(caCert)

tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS12,
    RootCAs:    caCertPool,
}

adapter, err := arangoadapter.NewAdapter(
    arangoadapter.WithEndpoints("https://localhost:8529"),
    arangoadapter.WithAuthentication("root", "password"),
    arangoadapter.WithTLSConfig(tlsConfig),
)
```

### Cluster Configuration

```go
// Connect to an ArangoDB cluster with multiple coordinators
adapter, err := arangoadapter.NewAdapter(
    arangoadapter.WithEndpoints(
        "http://coordinator1:8529",
        "http://coordinator2:8529",
        "http://coordinator3:8529",
    ),
    arangoadapter.WithAuthentication("root", "password"),
)
```

The adapter uses round-robin load balancing across all endpoints.

### Using an Existing Client

If you already have an ArangoDB client configured, you can use it directly:

```go
import (
    "github.com/arangodb/go-driver/v2/arangodb"
    "github.com/arangodb/go-driver/v2/connection"
)

// Your existing client setup
endpoint := connection.NewRoundRobinEndpoints([]string{"http://localhost:8529"})
config := connection.DefaultHTTP2ConfigurationWrapper(endpoint, false)
config.Authentication = connection.NewBasicAuth("root", "password")
conn := connection.NewHttp2Connection(config)
client := arangodb.NewClient(conn)

// Create adapter from existing client
adapter, err := arangoadapter.NewAdapterFromClient(client, "casbin", "casbin_rule")
```

## API Reference

### Adapter Methods

The adapter implements all required Casbin interfaces:

#### Loading and Saving

- `LoadPolicy(model)` - Load all policies from database
- `LoadPolicyCtx(ctx, model)` - Load with context support
- `SavePolicy(model)` - Save all policies (replaces existing)
- `SavePolicyCtx(ctx, model)` - Save with context support

#### Single Policy Operations

- `AddPolicy(sec, ptype, rule)` - Add a single policy
- `AddPolicyCtx(ctx, sec, ptype, rule)` - Add with context
- `RemovePolicy(sec, ptype, rule)` - Remove a single policy
- `RemovePolicyCtx(ctx, sec, ptype, rule)` - Remove with context
- `UpdatePolicy(sec, ptype, oldRule, newRule)` - Update a policy

#### Batch Operations

- `AddPolicies(sec, ptype, rules)` - Add multiple policies
- `RemovePolicies(sec, ptype, rules)` - Remove multiple policies
- `UpdatePolicies(sec, ptype, oldRules, newRules)` - Update multiple policies

#### Filtered Operations

- `RemoveFilteredPolicy(sec, ptype, fieldIndex, fieldValues...)` - Remove policies matching a filter
- `RemoveFilteredPolicyCtx(ctx, sec, ptype, fieldIndex, fieldValues...)` - Remove with context
- `UpdateFilteredPolicies(sec, ptype, newPolicies, fieldIndex, fieldValues...)` - Update policies matching a filter

## Data Structure

Policies are stored as documents in ArangoDB:

```json
{
  "_key": "auto-generated-by-arangodb",
  "ptype": "p",
  "v0": "alice",
  "v1": "data1",
  "v2": "read",
  "v3": "",
  "v4": "",
  "v5": ""
}
```

- `ptype`: Policy type (p, g, p2, g2, etc.)
- `v0-v5`: Up to 6 values per rule (Casbin's limit)

## Example Policy Model

Here's a simple RBAC model:

```ini
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
```

Save this as `model.conf` and you're ready to go.

## Running with Docker

Need a quick ArangoDB instance for testing?

```bash
docker run -e ARANGO_ROOT_PASSWORD=password -p 8529:8529 arangodb/arangodb:latest
```

Then connect to `http://localhost:8529` with username `root` and password `password`.

## Examples

Check out the [examples](./examples) directory for more:

- **[basic](./examples/basic)** - Simple usage with RBAC
- **[tls](./examples/tls)** - Secure connection with TLS
- **[cluster](./examples/cluster)** - Multi-coordinator cluster setup

## Performance Tips

1. **Use batch operations** - `AddPolicies()` is much faster than multiple `AddPolicy()` calls
2. **Use context timeouts** - Always set reasonable timeouts with the `*Ctx()` methods
3. **Consider indexes** - For large policy sets, add indexes on `ptype` and frequently queried `v*` fields in ArangoDB

## Thread Safety

The adapter uses a mutex to protect concurrent writes, so it's safe to use from multiple goroutines.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Found a bug or want to add a feature? Pull requests are welcome!

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Related Projects

- [Casbin](https://github.com/casbin/casbin) - The authorization library this adapter works with
- [ArangoDB Go Driver](https://github.com/arangodb/go-driver) - Official Go driver for ArangoDB

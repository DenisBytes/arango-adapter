package arangoadapter

import (
	"context"
	"testing"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/connection"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
)

// Helper function to create a test adapter
// You'll need a running ArangoDB instance for these tests
func setupTestAdapter(t *testing.T) *Adapter {
	adapter, err := NewAdapter(
		WithEndpoints("http://localhost:8529"),
		WithAuthentication("root", ""),
		WithDatabase("casbin_test"),
		WithCollection("casbin_rule_test"),
	)
	if err != nil {
		t.Skipf("Could not connect to ArangoDB: %v (skipping test)", err)
	}

	return adapter
}

// Helper function to create a test adapter using the old method (for backward compatibility tests)
func setupTestAdapterFromClient(t *testing.T) *Adapter {
	endpoint := connection.NewRoundRobinEndpoints([]string{"http://localhost:8529"})
	config := connection.DefaultHTTP2ConfigurationWrapper(endpoint, false)
	config.Authentication = connection.NewBasicAuth("root", "")
	conn := connection.NewHttp2Connection(config)

	client := arangodb.NewClient(conn)

	adapter, err := NewAdapterFromClient(client, "casbin_test_old", "casbin_rule_test_old")
	if err != nil {
		t.Skipf("Could not connect to ArangoDB: %v (skipping test)", err)
	}

	return adapter
}

// Clean up test database
func teardownTestAdapter(t *testing.T, adapter *Adapter) {
	ctx := context.Background()
	// Try to get and remove the test database
	if db, err := adapter.client.Database(ctx, adapter.databaseName); err == nil {
		db.Remove(ctx)
	}
}

func TestNewAdapter(t *testing.T) {
	adapter := setupTestAdapter(t)
	defer teardownTestAdapter(t, adapter)

	if adapter == nil {
		t.Fatal("Adapter should not be nil")
	}

	if adapter.databaseName != "casbin_test" {
		t.Errorf("Expected database name 'casbin_test', got '%s'", adapter.databaseName)
	}

	if adapter.collectionName != "casbin_rule_test" {
		t.Errorf("Expected collection name 'casbin_rule_test', got '%s'", adapter.collectionName)
	}
}

func TestLoadAndSavePolicy(t *testing.T) {
	adapter := setupTestAdapter(t)
	defer teardownTestAdapter(t, adapter)

	// Create a simple model
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")

	// Add some test policies directly to the model
	m.AddPolicy("p", "p", []string{"alice", "data1", "read"})
	m.AddPolicy("p", "p", []string{"bob", "data2", "write"})

	// Save to database
	err := adapter.SavePolicy(m)
	if err != nil {
		t.Fatalf("Failed to save policy: %v", err)
	}

	// Create a fresh model and load from database
	m2 := model.NewModel()
	m2.AddDef("r", "r", "sub, obj, act")
	m2.AddDef("p", "p", "sub, obj, act")
	m2.AddDef("e", "e", "some(where (p.eft == allow))")
	m2.AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")

	err = adapter.LoadPolicy(m2)
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// Verify the policies were loaded correctly
	policies, _ := m2.GetPolicy("p", "p")
	if len(policies) != 2 {
		t.Errorf("Expected 2 policies, got %d", len(policies))
	}
}

func TestAddPolicy(t *testing.T) {
	adapter := setupTestAdapter(t)
	defer teardownTestAdapter(t, adapter)

	err := adapter.AddPolicy("p", "p", []string{"charlie", "data3", "read"})
	if err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}

	// Verify it was added
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")

	err = adapter.LoadPolicy(m)
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	policies, _ := m.GetPolicy("p", "p")
	if len(policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(policies))
	}

	if len(policies) > 0 {
		if policies[0][0] != "charlie" || policies[0][1] != "data3" || policies[0][2] != "read" {
			t.Errorf("Policy values don't match: %v", policies[0])
		}
	}
}

func TestRemovePolicy(t *testing.T) {
	adapter := setupTestAdapter(t)
	defer teardownTestAdapter(t, adapter)

	// Add a policy
	err := adapter.AddPolicy("p", "p", []string{"dave", "data4", "write"})
	if err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}

	// Remove it
	err = adapter.RemovePolicy("p", "p", []string{"dave", "data4", "write"})
	if err != nil {
		t.Fatalf("Failed to remove policy: %v", err)
	}

	// Verify it's gone
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")

	err = adapter.LoadPolicy(m)
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	policies, _ := m.GetPolicy("p", "p")
	if len(policies) != 0 {
		t.Errorf("Expected 0 policies, got %d", len(policies))
	}
}

func TestAddPolicies(t *testing.T) {
	adapter := setupTestAdapter(t)
	defer teardownTestAdapter(t, adapter)

	rules := [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"charlie", "data3", "read"},
	}

	err := adapter.AddPolicies("p", "p", rules)
	if err != nil {
		t.Fatalf("Failed to add policies: %v", err)
	}

	// Verify they were added
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")

	err = adapter.LoadPolicy(m)
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	policies, _ := m.GetPolicy("p", "p")
	if len(policies) != 3 {
		t.Errorf("Expected 3 policies, got %d", len(policies))
	}
}

func TestRemoveFilteredPolicy(t *testing.T) {
	adapter := setupTestAdapter(t)
	defer teardownTestAdapter(t, adapter)

	// Add some policies
	rules := [][]string{
		{"alice", "data1", "read"},
		{"alice", "data2", "read"},
		{"bob", "data1", "write"},
	}

	err := adapter.AddPolicies("p", "p", rules)
	if err != nil {
		t.Fatalf("Failed to add policies: %v", err)
	}

	// Remove all policies for alice
	err = adapter.RemoveFilteredPolicy("p", "p", 0, "alice")
	if err != nil {
		t.Fatalf("Failed to remove filtered policy: %v", err)
	}

	// Verify only bob's policy remains
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")

	err = adapter.LoadPolicy(m)
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	policies, _ := m.GetPolicy("p", "p")
	if len(policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(policies))
	}

	if len(policies) > 0 && policies[0][0] != "bob" {
		t.Errorf("Expected bob's policy, got %v", policies[0])
	}
}

func TestUpdatePolicy(t *testing.T) {
	adapter := setupTestAdapter(t)
	defer teardownTestAdapter(t, adapter)

	// Add a policy
	err := adapter.AddPolicy("p", "p", []string{"alice", "data1", "read"})
	if err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}

	// Update it
	err = adapter.UpdatePolicy("p", "p", []string{"alice", "data1", "read"}, []string{"alice", "data1", "write"})
	if err != nil {
		t.Fatalf("Failed to update policy: %v", err)
	}

	// Verify the update
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")

	err = adapter.LoadPolicy(m)
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	policies, _ := m.GetPolicy("p", "p")
	if len(policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(policies))
	}

	if len(policies) > 0 && policies[0][2] != "write" {
		t.Errorf("Expected action 'write', got '%s'", policies[0][2])
	}
}

func TestLoadFilteredPolicy(t *testing.T) {
	adapter := setupTestAdapter(t)
	defer teardownTestAdapter(t, adapter)

	// Add some test policies first
	rules := [][]string{
		{"alice", "data1", "read"},
		{"alice", "data2", "write"},
		{"bob", "data1", "read"},
		{"bob", "data2", "write"},
	}
	err := adapter.AddPolicies("p", "p", rules)
	if err != nil {
		t.Fatalf("Failed to add policies: %v", err)
	}

	// Test filtered loading - only alice's policies
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")

	filter := Filter{
		V0: []string{"alice"},
	}

	err = adapter.LoadFilteredPolicy(m, filter)
	if err != nil {
		t.Fatalf("Failed to load filtered policy: %v", err)
	}

	// Verify only alice's policies were loaded
	policies, _ := m.GetPolicy("p", "p")
	if len(policies) != 2 {
		t.Errorf("Expected 2 policies for alice, got %d", len(policies))
	}

	// Check that adapter knows it's filtered
	if !adapter.IsFiltered() {
		t.Error("Adapter should report as filtered")
	}

	// Verify the loaded policies are alice's
	for _, p := range policies {
		if p[0] != "alice" {
			t.Errorf("Expected policy for alice, got %v", p)
		}
	}
}

func TestIsFiltered(t *testing.T) {
	adapter := setupTestAdapter(t)
	defer teardownTestAdapter(t, adapter)

	// Initially should not be filtered
	if adapter.IsFiltered() {
		t.Error("New adapter should not be filtered")
	}

	// After normal load, should not be filtered
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")

	adapter.LoadPolicy(m)
	if adapter.IsFiltered() {
		t.Error("After LoadPolicy(), adapter should not be filtered")
	}

	// After filtered load, should be filtered
	filter := Filter{V0: []string{"alice"}}
	adapter.LoadFilteredPolicy(m, filter)
	if !adapter.IsFiltered() {
		t.Error("After LoadFilteredPolicy(), adapter should be filtered")
	}
}

func TestWithCasbinEnforcer(t *testing.T) {
	adapter := setupTestAdapter(t)
	defer teardownTestAdapter(t, adapter)

	// Create a model config
	modelText := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`

	m, err := model.NewModelFromString(modelText)
	if err != nil {
		t.Fatalf("Failed to create model: %v", err)
	}

	// Create enforcer
	e, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		t.Fatalf("Failed to create enforcer: %v", err)
	}

	// Add some policies
	e.AddPolicy("alice", "data1", "read")
	e.AddPolicy("bob", "data2", "write")

	// Test enforcement
	if allowed, _ := e.Enforce("alice", "data1", "read"); !allowed {
		t.Error("Alice should be able to read data1")
	}

	if allowed, _ := e.Enforce("alice", "data2", "write"); allowed {
		t.Error("Alice should not be able to write data2")
	}

	if allowed, _ := e.Enforce("bob", "data2", "write"); !allowed {
		t.Error("Bob should be able to write data2")
	}

	// Save and reload
	e.SavePolicy()

	e2, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		t.Fatalf("Failed to create second enforcer: %v", err)
	}

	// Verify policies persisted
	if allowed, _ := e2.Enforce("alice", "data1", "read"); !allowed {
		t.Error("Alice should still be able to read data1 after reload")
	}
}

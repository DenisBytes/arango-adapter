package arangoadapter

import (
	"context"
	"errors"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
)

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

func teardownTestAdapter(t *testing.T, adapter *Adapter) {
	ctx := context.Background()
	if db, err := adapter.client.Database(ctx, adapter.databaseName); err == nil {
		_ = db.Remove(ctx)
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
	_ = m.AddPolicy("p", "p", []string{"alice", "data1", "read"})
	_ = m.AddPolicy("p", "p", []string{"bob", "data2", "write"})

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

	_ = adapter.LoadPolicy(m)
	if adapter.IsFiltered() {
		t.Error("After LoadPolicy(), adapter should not be filtered")
	}

	// After filtered load, should be filtered
	filter := Filter{V0: []string{"alice"}}
	_ = adapter.LoadFilteredPolicy(m, filter)
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
	_, _ = e.AddPolicy("alice", "data1", "read")
	_, _ = e.AddPolicy("bob", "data2", "write")

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
	_ = e.SavePolicy()

	e2, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		t.Fatalf("Failed to create second enforcer: %v", err)
	}

	// Verify policies persisted
	if allowed, _ := e2.Enforce("alice", "data1", "read"); !allowed {
		t.Error("Alice should still be able to read data1 after reload")
	}
}

func TestTransaction(t *testing.T) {
	adapter := setupTestAdapter(t)
	defer teardownTestAdapter(t, adapter)

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

	e, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		t.Fatalf("Failed to create enforcer: %v", err)
	}

	// Test successful transaction
	err = adapter.Transaction(e, func(e casbin.IEnforcer) error {
		_, _ = e.AddPolicy("alice", "data1", "read")
		_, _ = e.AddPolicy("bob", "data2", "write")
		return nil
	})

	if err != nil {
		t.Fatalf("Transaction failed: %v", err)
	}

	// Verify policies were committed
	_ = e.LoadPolicy()
	if allowed, _ := e.Enforce("alice", "data1", "read"); !allowed {
		t.Error("Transaction should have committed alice's policy")
	}

	// Test failed transaction (should rollback)
	err = adapter.Transaction(e, func(e casbin.IEnforcer) error {
		_, _ = e.AddPolicy("charlie", "data3", "read")
		return errors.New("intentional error")
	})

	if err == nil {
		t.Error("Expected transaction to fail")
	}

	// Verify charlie's policy was rolled back
	_ = e.LoadPolicy()
	if allowed, _ := e.Enforce("charlie", "data3", "read"); allowed {
		t.Error("Failed transaction should have been rolled back")
	}
}

func TestBeginTransaction(t *testing.T) {
	adapter := setupTestAdapter(t)
	defer teardownTestAdapter(t, adapter)

	ctx := context.Background()

	// Begin transaction
	txCtx, err := adapter.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("Failed to begin transaction: %v", err)
	}

	// Get transaction adapter
	txAdapter := txCtx.GetAdapter()

	// Add policies within transaction
	err = txAdapter.AddPolicy("", "p", []string{"alice", "data1", "read"})
	if err != nil {
		t.Fatalf("Failed to add policy in transaction: %v", err)
	}

	// Commit transaction
	err = txCtx.Commit()
	if err != nil {
		t.Fatalf("Failed to commit transaction: %v", err)
	}

	// Verify policy was committed
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")

	_ = adapter.LoadPolicy(m)
	policies, _ := m.GetPolicy("p", "p")
	if len(policies) != 1 {
		t.Errorf("Expected 1 policy after commit, got %d", len(policies))
	}
}

func TestTransactionRollback(t *testing.T) {
	adapter := setupTestAdapter(t)
	defer teardownTestAdapter(t, adapter)

	ctx := context.Background()

	// Add initial policy
	_ = adapter.AddPolicy("", "p", []string{"alice", "data1", "read"})

	// Begin transaction
	txCtx, err := adapter.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("Failed to begin transaction: %v", err)
	}

	txAdapter := txCtx.GetAdapter()

	// Add policy in transaction
	_ = txAdapter.AddPolicy("", "p", []string{"bob", "data2", "write"})

	// Rollback
	err = txCtx.Rollback()
	if err != nil {
		t.Fatalf("Failed to rollback: %v", err)
	}

	// Verify bob's policy was not added
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")

	_ = adapter.LoadPolicy(m)
	policies, _ := m.GetPolicy("p", "p")
	if len(policies) != 1 {
		t.Errorf("Expected 1 policy (alice only), got %d", len(policies))
	}
}

func TestPreview(t *testing.T) {
	adapter := setupTestAdapter(t)
	defer teardownTestAdapter(t, adapter)

	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")

	rules := []CasbinRule{
		{Ptype: "p", V0: "alice", V1: "data1", V2: "read"},
		{Ptype: "p", V0: "bob", V1: "data2", V2: "write"},
		{Ptype: "p", V0: "charlie", V1: "data3", V2: "read"},
	}

	// Add alice and bob to the model — Preview should filter them out as duplicates
	_ = m.AddPolicy("p", "p", []string{"alice", "data1", "read"})
	_ = m.AddPolicy("p", "p", []string{"bob", "data2", "write"})

	err := adapter.Preview(&rules, m)
	if err != nil {
		t.Fatalf("Preview failed: %v", err)
	}

	// Only charlie (the non-duplicate) should remain
	if len(rules) != 1 {
		t.Errorf("Expected 1 non-duplicate rule, got %d", len(rules))
	}

	if len(rules) > 0 && rules[0].V0 != "charlie" {
		t.Errorf("Expected charlie's rule to remain, got %s", rules[0].V0)
	}
}

func TestClose(t *testing.T) {
	adapter := setupTestAdapter(t)
	defer teardownTestAdapter(t, adapter)

	// Close should not error (even though it's a no-op for ArangoDB)
	err := adapter.Close()
	if err != nil {
		t.Errorf("Close should not error: %v", err)
	}
}

func TestNewFilteredAdapter(t *testing.T) {
	adapter, err := NewFilteredAdapter(
		WithEndpoints("http://localhost:8529"),
		WithAuthentication("root", ""),
		WithDatabase("casbin_test_filtered"),
		WithCollection("casbin_rule_filtered"),
	)

	if err != nil {
		t.Skipf("Could not create filtered adapter: %v", err)
	}

	defer teardownTestAdapter(t, adapter)

	// Filtered adapter should report as filtered from the start
	if !adapter.IsFiltered() {
		t.Error("NewFilteredAdapter should create filtered adapter")
	}
}

func TestRemovePolicies(t *testing.T) {
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

	// Batch-remove alice and charlie
	err = adapter.RemovePolicies("p", "p", [][]string{
		{"alice", "data1", "read"},
		{"charlie", "data3", "read"},
	})
	if err != nil {
		t.Fatalf("Failed to remove policies: %v", err)
	}

	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")

	_ = adapter.LoadPolicy(m)
	policies, _ := m.GetPolicy("p", "p")
	if len(policies) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(policies))
	}
	if policies[0][0] != "bob" {
		t.Errorf("Expected bob's policy to remain, got %v", policies[0])
	}

	// Empty rules should be a no-op
	err = adapter.RemovePolicies("p", "p", [][]string{})
	if err != nil {
		t.Errorf("Empty RemovePolicies should not error: %v", err)
	}
}

func TestUpdatePolicies(t *testing.T) {
	adapter := setupTestAdapter(t)
	defer teardownTestAdapter(t, adapter)

	rules := [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
	}
	_ = adapter.AddPolicies("p", "p", rules)

	err := adapter.UpdatePolicies("p", "p",
		[][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}},
		[][]string{{"alice", "data1", "write"}, {"bob", "data2", "read"}},
	)
	if err != nil {
		t.Fatalf("Failed to update policies: %v", err)
	}

	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")
	_ = adapter.LoadPolicy(m)

	policies, _ := m.GetPolicy("p", "p")
	if len(policies) != 2 {
		t.Fatalf("Expected 2 policies, got %d", len(policies))
	}

	// Test mismatched lengths
	err = adapter.UpdatePolicies("p", "p",
		[][]string{{"alice", "data1", "write"}},
		[][]string{{"a", "b", "c"}, {"d", "e", "f"}},
	)
	if err == nil {
		t.Error("Expected error for mismatched old/new rule lengths")
	}
}

func TestUpdateFilteredPolicies(t *testing.T) {
	adapter := setupTestAdapter(t)
	defer teardownTestAdapter(t, adapter)

	rules := [][]string{
		{"alice", "data1", "read"},
		{"alice", "data2", "write"},
		{"bob", "data1", "read"},
	}
	_ = adapter.AddPolicies("p", "p", rules)

	// Replace alice's rules with new ones
	oldPolicies, err := adapter.UpdateFilteredPolicies("p", "p",
		[][]string{{"alice", "data3", "execute"}},
		0, "alice",
	)
	if err != nil {
		t.Fatalf("Failed to update filtered policies: %v", err)
	}

	if len(oldPolicies) != 2 {
		t.Errorf("Expected 2 old policies returned, got %d", len(oldPolicies))
	}

	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")
	_ = adapter.LoadPolicy(m)

	policies, _ := m.GetPolicy("p", "p")
	if len(policies) != 2 {
		t.Fatalf("Expected 2 policies, got %d", len(policies))
	}
}

func TestRemoveFilteredPolicyFieldIndex(t *testing.T) {
	adapter := setupTestAdapter(t)
	defer teardownTestAdapter(t, adapter)

	rules := [][]string{
		{"alice", "data1", "read"},
		{"bob", "data1", "write"},
		{"charlie", "data2", "read"},
	}
	_ = adapter.AddPolicies("p", "p", rules)

	// Remove by fieldIndex=1 (v1="data1")
	err := adapter.RemoveFilteredPolicy("p", "p", 1, "data1")
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")
	_ = adapter.LoadPolicy(m)

	policies, _ := m.GetPolicy("p", "p")
	if len(policies) != 1 {
		t.Fatalf("Expected 1 policy remaining, got %d", len(policies))
	}
	if policies[0][0] != "charlie" {
		t.Errorf("Expected charlie's policy, got %v", policies[0])
	}
}

func TestLoadFilteredPolicyUnknownType(t *testing.T) {
	adapter := setupTestAdapter(t)
	defer teardownTestAdapter(t, adapter)

	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")

	// Passing an unsupported type should return an error
	err := adapter.LoadFilteredPolicy(m, "invalid-filter")
	if err == nil {
		t.Error("Expected error for unsupported filter type")
	}
}

func TestNewBatchFilter(t *testing.T) {
	f1 := Filter{V0: []string{"alice"}}
	f2 := Filter{V0: []string{"bob"}}
	bf := NewBatchFilter(f1, f2)

	if len(bf.filters) != 2 {
		t.Errorf("Expected 2 filters, got %d", len(bf.filters))
	}
}

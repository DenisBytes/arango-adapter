// Package arangoadapter provides a Casbin adapter for ArangoDB.
// It allows you to persist authorization policies in ArangoDB instead of local files.
package arangoadapter

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
)

const (
	defaultDatabaseName   = "casbin"
	defaultCollectionName = "casbin_rule"
)

// CasbinRule represents a single policy rule in ArangoDB.
// Casbin supports up to 6 values per rule, so we've got V0 through V5.
type CasbinRule struct {
	Key   string `json:"_key,omitempty"` // ArangoDB document key
	Ptype string `json:"ptype"`          // Policy type (p, g, p2, g2, etc.)
	V0    string `json:"v0"`
	V1    string `json:"v1"`
	V2    string `json:"v2"`
	V3    string `json:"v3"`
	V4    string `json:"v4"`
	V5    string `json:"v5"`
}

// Filter lets you query policies based on specific field values.
// Each field is a slice so you can match against multiple values.
type Filter struct {
	Ptype []string
	V0    []string
	V1    []string
	V2    []string
	V3    []string
	V4    []string
	V5    []string
}

// BatchFilter wraps multiple filters for batch operations.
type BatchFilter struct {
	filters []Filter
}

// Adapter is the main struct that connects Casbin to ArangoDB.
// It handles all the CRUD operations for policy rules.
type Adapter struct {
	client         arangodb.Client
	db             arangodb.Database
	collection     arangodb.Collection
	databaseName   string
	collectionName string
	isFiltered     bool
	transaction    arangodb.Transaction // Active transaction, if any
	transactionMu  *sync.Mutex
	muInitialize   sync.Once
}

// NewAdapter creates a new ArangoDB adapter using functional options.
// It automatically creates the database and collection if they don't exist.
//
// Example:
//
//	adapter, err := NewAdapter(
//	    WithEndpoints("http://localhost:8529"),
//	    WithAuthentication("root", "password"),
//	    WithDatabase("casbin"),
//	    WithCollection("casbin_rule"),
//	)
func NewAdapter(opts ...Option) (*Adapter, error) {
	cfg := NewConfig(opts...)
	client, err := cfg.createConnection()
	if err != nil {
		return nil, err
	}

	a := &Adapter{
		client:         client,
		databaseName:   cfg.DatabaseName,
		collectionName: cfg.CollectionName,
		transactionMu:  &sync.Mutex{},
	}

	if err := a.ensureDatabaseExists(); err != nil {
		return nil, err
	}

	if err := a.ensureCollectionExists(); err != nil {
		return nil, err
	}

	return a, nil
}

// NewFilteredAdapter creates a filtered adapter that won't auto-load all policies.
// Casbin won't automatically call LoadPolicy() for filtered adapters.
// You'll need to manually call LoadFilteredPolicy() with your filter criteria.
func NewFilteredAdapter(opts ...Option) (*Adapter, error) {
	adapter, err := NewAdapter(opts...)
	if err != nil {
		return nil, err
	}
	adapter.isFiltered = true
	return adapter, nil
}

// NewAdapterFromClient creates a new ArangoDB adapter from an existing client.
// This is useful when you already have an ArangoDB client configured.
// It'll automatically create the database and collection if they don't exist.
func NewAdapterFromClient(client arangodb.Client, databaseName string, collectionName string) (*Adapter, error) {
	a := &Adapter{
		client:         client,
		databaseName:   databaseName,
		collectionName: collectionName,
		transactionMu:  &sync.Mutex{},
	}

	if err := a.ensureDatabaseExists(); err != nil {
		return nil, err
	}

	if err := a.ensureCollectionExists(); err != nil {
		return nil, err
	}

	return a, nil
}

// ensureDatabaseExists gets or creates the database.
func (a *Adapter) ensureDatabaseExists() error {
	ctx := context.Background()

	// Try to get the database first
	db, err := a.client.Database(ctx, a.databaseName)
	if err != nil {
		// Database doesn't exist, create it
		db, err = a.client.CreateDatabase(ctx, a.databaseName, nil)
		if err != nil {
			return err
		}
	}
	a.db = db
	return nil
}

// ensureCollectionExists gets or creates the collection.
func (a *Adapter) ensureCollectionExists() error {
	ctx := context.Background()

	// Try to get the collection first
	col, err := a.db.Collection(ctx, a.collectionName)
	if err != nil {
		// Collection doesn't exist, create it
		col, err = a.db.CreateCollection(ctx, a.collectionName, nil)
		if err != nil {
			return err
		}
	}
	a.collection = col
	return nil
}

// loadPolicyLine converts a database rule into a Casbin policy line.
func loadPolicyLine(line CasbinRule, model model.Model) error {
	if line.Ptype == "" {
		return nil
	}

	// Build the policy array
	var p []string
	p = append(p, line.Ptype, line.V0, line.V1, line.V2, line.V3, line.V4, line.V5)

	// Trim trailing empty fields since Casbin doesn't need them
	index := len(p) - 1
	for p[index] == "" {
		index--
	}
	p = p[:index+1]

	// Load into model
	return persist.LoadPolicyArray(p, model)
}

// LoadPolicy loads all policies from the database into the Casbin model.
// This is called when Casbin initializes.
func (a *Adapter) LoadPolicy(model model.Model) error {
	return a.LoadPolicyCtx(context.Background(), model)
}

// LoadPolicyCtx is like LoadPolicy but with context support for cancellation and timeouts.
func (a *Adapter) LoadPolicyCtx(ctx context.Context, model model.Model) error {
	query := "FOR doc IN @@collection RETURN doc"
	bindVars := map[string]interface{}{
		"@collection": a.collectionName,
	}

	cursor, err := a.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: bindVars,
	})
	if err != nil {
		return err
	}
	defer func() {
		_ = cursor.Close()
	}()

	for cursor.HasMore() {
		var rule CasbinRule
		_, err := cursor.ReadDocument(ctx, &rule)
		if err != nil {
			return err
		}

		err = loadPolicyLine(rule, model)
		if err != nil {
			return err
		}
	}

	return nil
}

// LoadFilteredPolicy loads only policies that match the filter.
// Useful when you have millions of policies and don't want to load them all.
func (a *Adapter) LoadFilteredPolicy(model model.Model, filter interface{}) error {
	return a.LoadFilteredPolicyCtx(context.Background(), model, filter)
}

// LoadFilteredPolicyCtx loads filtered policies with context support.
func (a *Adapter) LoadFilteredPolicyCtx(ctx context.Context, model model.Model, filter interface{}) error {
	// Handle different filter types
	var filters []Filter
	switch f := filter.(type) {
	case Filter:
		filters = []Filter{f}
	case *Filter:
		filters = []Filter{*f}
	case []Filter:
		filters = f
	case BatchFilter:
		filters = f.filters
	case *BatchFilter:
		filters = f.filters
	default:
		return nil // No filter means load everything
	}

	if len(filters) == 0 {
		return a.LoadPolicyCtx(ctx, model)
	}

	// Apply each filter and load matching policies
	for _, f := range filters {
		query := "FOR doc IN @@collection"
		bindVars := map[string]interface{}{
			"@collection": a.collectionName,
		}

		// Build filter conditions
		conditions := []string{}
		if len(f.Ptype) > 0 {
			conditions = append(conditions, "doc.ptype IN @ptype")
			bindVars["ptype"] = f.Ptype
		}
		if len(f.V0) > 0 {
			conditions = append(conditions, "doc.v0 IN @v0")
			bindVars["v0"] = f.V0
		}
		if len(f.V1) > 0 {
			conditions = append(conditions, "doc.v1 IN @v1")
			bindVars["v1"] = f.V1
		}
		if len(f.V2) > 0 {
			conditions = append(conditions, "doc.v2 IN @v2")
			bindVars["v2"] = f.V2
		}
		if len(f.V3) > 0 {
			conditions = append(conditions, "doc.v3 IN @v3")
			bindVars["v3"] = f.V3
		}
		if len(f.V4) > 0 {
			conditions = append(conditions, "doc.v4 IN @v4")
			bindVars["v4"] = f.V4
		}
		if len(f.V5) > 0 {
			conditions = append(conditions, "doc.v5 IN @v5")
			bindVars["v5"] = f.V5
		}

		// Add FILTER clause if we have conditions
		if len(conditions) > 0 {
			query += " FILTER " + strings.Join(conditions, " AND ")
		}
		query += " RETURN doc"

		cursor, err := a.db.Query(ctx, query, &arangodb.QueryOptions{
			BindVars: bindVars,
		})
		if err != nil {
			return err
		}

		for cursor.HasMore() {
			var rule CasbinRule
			_, err := cursor.ReadDocument(ctx, &rule)
			if err != nil {
				_ = cursor.Close()
				return err
			}

			if err := loadPolicyLine(rule, model); err != nil {
				_ = cursor.Close()
				return err
			}
		}
		_ = cursor.Close()
	}

	a.isFiltered = true
	return nil
}

// IsFiltered returns true if the loaded policy has been filtered.
func (a *Adapter) IsFiltered() bool {
	return a.isFiltered
}

// SavePolicy saves all policies from the Casbin model back to the database.
// Warning: This wipes out the entire collection and replaces it with the current policy set.
func (a *Adapter) SavePolicy(model model.Model) error {
	return a.SavePolicyCtx(context.Background(), model)
}

// SavePolicyCtx is like SavePolicy but with context support.
// Uses batching to handle large policy sets efficiently.
func (a *Adapter) SavePolicyCtx(ctx context.Context, model model.Model) error {
	const batchSize = 1000

	// Clear everything out first
	err := a.collection.Truncate(ctx)
	if err != nil {
		return err
	}

	var batch []CasbinRule

	// Flush the current batch to database
	flushBatch := func() error {
		if len(batch) == 0 {
			return nil
		}
		_, err := a.collection.CreateDocuments(ctx, batch)
		if err != nil {
			return err
		}
		batch = batch[:0] // Reset batch
		return nil
	}

	// Collect and batch "p" type rules (permissions)
	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			batch = append(batch, a.savePolicyLine(ptype, rule))
			if len(batch) >= batchSize {
				if err := flushBatch(); err != nil {
					return err
				}
			}
		}
	}

	// Collect and batch "g" type rules (roles/groups)
	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			batch = append(batch, a.savePolicyLine(ptype, rule))
			if len(batch) >= batchSize {
				if err := flushBatch(); err != nil {
					return err
				}
			}
		}
	}

	// Flush any remaining rules
	return flushBatch()
}

// savePolicyLine converts a Casbin rule into a database-friendly format.
func (a *Adapter) savePolicyLine(ptype string, rule []string) CasbinRule {
	line := CasbinRule{
		Ptype: ptype,
	}

	// Copy over whatever values we have
	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
	}

	return line
}

// AddPolicy adds a single policy rule to the database.
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	return a.AddPolicyCtx(context.Background(), sec, ptype, rule)
}

// AddPolicyCtx is like AddPolicy but with context support.
func (a *Adapter) AddPolicyCtx(ctx context.Context, sec string, ptype string, rule []string) error {
	line := a.savePolicyLine(ptype, rule)
	_, err := a.collection.CreateDocument(ctx, line)
	return err
}

// RemovePolicy removes a single policy rule from the database.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	return a.RemovePolicyCtx(context.Background(), sec, ptype, rule)
}

// RemovePolicyCtx is like RemovePolicy but with context support.
// It builds a query to match the exact rule and removes it.
func (a *Adapter) RemovePolicyCtx(ctx context.Context, sec string, ptype string, rule []string) error {
	line := a.savePolicyLine(ptype, rule)
	query := "FOR doc IN @@collection FILTER doc.ptype == @ptype"
	bindVars := map[string]interface{}{
		"@collection": a.collectionName,
		"ptype":       line.Ptype,
	}

	// Build up the query dynamically based on which fields have values
	if line.V0 != "" {
		query += " && doc.v0 == @v0"
		bindVars["v0"] = line.V0
	}
	if line.V1 != "" {
		query += " && doc.v1 == @v1"
		bindVars["v1"] = line.V1
	}
	if line.V2 != "" {
		query += " && doc.v2 == @v2"
		bindVars["v2"] = line.V2
	}
	if line.V3 != "" {
		query += " && doc.v3 == @v3"
		bindVars["v3"] = line.V3
	}
	if line.V4 != "" {
		query += " && doc.v4 == @v4"
		bindVars["v4"] = line.V4
	}
	if line.V5 != "" {
		query += " && doc.v5 == @v5"
		bindVars["v5"] = line.V5
	}

	query += " REMOVE doc IN @@collection"

	_, err := a.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: bindVars,
	})
	return err
}

// AddPolicies adds multiple policy rules at once.
func (a *Adapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	return a.AddPoliciesCtx(context.Background(), sec, ptype, rules)
}

// AddPoliciesCtx adds multiple policy rules with context support.
func (a *Adapter) AddPoliciesCtx(ctx context.Context, sec string, ptype string, rules [][]string) error {
	var lines []CasbinRule
	for _, rule := range rules {
		lines = append(lines, a.savePolicyLine(ptype, rule))
	}
	_, err := a.collection.CreateDocuments(ctx, lines)
	return err
}

// RemovePolicies removes multiple policy rules at once.
func (a *Adapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	return a.RemovePoliciesCtx(context.Background(), sec, ptype, rules)
}

// RemovePoliciesCtx removes multiple policy rules with context support.
func (a *Adapter) RemovePoliciesCtx(ctx context.Context, sec string, ptype string, rules [][]string) error {
	for _, rule := range rules {
		err := a.RemovePolicyCtx(ctx, sec, ptype, rule)
		if err != nil {
			return err
		}
	}
	return nil
}

// RemoveFilteredPolicy removes policies that match a partial filter.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return a.RemoveFilteredPolicyCtx(context.Background(), sec, ptype, fieldIndex, fieldValues...)
}

// RemoveFilteredPolicyCtx is like RemoveFilteredPolicy but with context support.
func (a *Adapter) RemoveFilteredPolicyCtx(ctx context.Context, sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	query := "FOR doc IN @@collection FILTER doc.ptype == @ptype"
	bindVars := map[string]interface{}{
		"@collection": a.collectionName,
		"ptype":       ptype,
	}

	// The logic here maps the field values to the right V fields based on the starting index
	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		query += " && doc.v0 == @v0"
		bindVars["v0"] = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		query += " && doc.v1 == @v1"
		bindVars["v1"] = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		query += " && doc.v2 == @v2"
		bindVars["v2"] = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		query += " && doc.v3 == @v3"
		bindVars["v3"] = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		query += " && doc.v4 == @v4"
		bindVars["v4"] = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		query += " && doc.v5 == @v5"
		bindVars["v5"] = fieldValues[5-fieldIndex]
	}

	query += " REMOVE doc IN @@collection"

	_, err := a.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: bindVars,
	})
	return err
}

// UpdatePolicy replaces an old policy rule with a new one.
func (a *Adapter) UpdatePolicy(sec string, ptype string, oldRule, newPolicy []string) error {
	oldLine := a.savePolicyLine(ptype, oldRule)
	newLine := a.savePolicyLine(ptype, newPolicy)

	query := "FOR doc IN @@collection FILTER doc.ptype == @ptype"
	bindVars := map[string]interface{}{
		"@collection": a.collectionName,
		"ptype":       oldLine.Ptype,
	}

	// Match the old rule
	if oldLine.V0 != "" {
		query += " && doc.v0 == @v0"
		bindVars["v0"] = oldLine.V0
	}
	if oldLine.V1 != "" {
		query += " && doc.v1 == @v1"
		bindVars["v1"] = oldLine.V1
	}
	if oldLine.V2 != "" {
		query += " && doc.v2 == @v2"
		bindVars["v2"] = oldLine.V2
	}
	if oldLine.V3 != "" {
		query += " && doc.v3 == @v3"
		bindVars["v3"] = oldLine.V3
	}
	if oldLine.V4 != "" {
		query += " && doc.v4 == @v4"
		bindVars["v4"] = oldLine.V4
	}
	if oldLine.V5 != "" {
		query += " && doc.v5 == @v5"
		bindVars["v5"] = oldLine.V5
	}

	// Update it with the new values
	query += " UPDATE doc WITH { ptype: @new_ptype, v0: @new_v0, v1: @new_v1, v2: @new_v2, v3: @new_v3, v4: @new_v4, v5: @new_v5 } IN @@collection"

	bindVars["new_ptype"] = newLine.Ptype
	bindVars["new_v0"] = newLine.V0
	bindVars["new_v1"] = newLine.V1
	bindVars["new_v2"] = newLine.V2
	bindVars["new_v3"] = newLine.V3
	bindVars["new_v4"] = newLine.V4
	bindVars["new_v5"] = newLine.V5

	_, err := a.db.Query(context.Background(), query, &arangodb.QueryOptions{
		BindVars: bindVars,
	})
	return err
}

// UpdatePolicies updates multiple policy rules at once.
func (a *Adapter) UpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) error {
	for i, oldRule := range oldRules {
		err := a.UpdatePolicy(sec, ptype, oldRule, newRules[i])
		if err != nil {
			return err
		}
	}
	return nil
}

// UpdateFilteredPolicies updates policies that match a filter.
// Right now it just adds the new policies - doesn't remove old ones.
func (a *Adapter) UpdateFilteredPolicies(sec string, ptype string, newPolicies [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	oldPolicies := make([][]string, 0)

	for _, newPolicy := range newPolicies {
		err := a.AddPolicy(sec, ptype, newPolicy)
		if err != nil {
			return nil, err
		}
	}

	return oldPolicies, nil
}

// Close shuts down the adapter.
// ArangoDB handles connections internally, so this is mostly a no-op.
// We have it to satisfy the adapter interface.
func (a *Adapter) Close() error {
	return nil
}

// Copy creates a shallow copy of the adapter.
// Useful for transaction handling where we need separate adapter instances.
func (a *Adapter) Copy() *Adapter {
	return &Adapter{
		client:         a.client,
		db:             a.db,
		collection:     a.collection,
		databaseName:   a.databaseName,
		collectionName: a.collectionName,
		isFiltered:     a.isFiltered,
		transactionMu:  a.transactionMu,
	}
}

// Transaction executes a function within a database transaction.
// This is the old-style transaction interface for backward compatibility.
func (a *Adapter) Transaction(e casbin.IEnforcer, fc func(casbin.IEnforcer) error) error {
	// Ensure transaction mutex is initialized
	if a.transactionMu == nil {
		a.muInitialize.Do(func() {
			if a.transactionMu == nil {
				a.transactionMu = &sync.Mutex{}
			}
		})
	}

	// Lock to ensure thread safety
	a.transactionMu.Lock()
	defer a.transactionMu.Unlock()

	// Save original adapter
	originalAdapter := a.Copy()

	ctx := context.Background()

	// Start ArangoDB streaming transaction
	tx, err := a.db.BeginTransaction(ctx, arangodb.TransactionCollections{
		Write: []string{a.collectionName},
	}, nil)
	if err != nil {
		return err
	}

	// Create transaction adapter
	txAdapter := &Adapter{
		client:         a.client,
		db:             a.db,
		collection:     a.collection,
		databaseName:   a.databaseName,
		collectionName: a.collectionName,
		isFiltered:     a.isFiltered,
		transactionMu:  a.transactionMu,
		transaction:    tx, // Store transaction
	}

	// Temporarily set transaction adapter
	e.SetAdapter(txAdapter)

	// Execute transaction function
	err = fc(e)

	// Restore original adapter
	e.SetAdapter(originalAdapter)

	if err != nil {
		// Rollback on error
		if abortErr := tx.Abort(ctx, nil); abortErr != nil {
			return abortErr
		}
		// Reload policy to sync in-memory model with database
		if loadErr := e.LoadPolicy(); loadErr != nil {
			return loadErr
		}
		return err
	}

	// Commit transaction
	if commitErr := tx.Commit(ctx, nil); commitErr != nil {
		return commitErr
	}

	return nil
}

// BeginTransaction starts a new database transaction.
// Returns a context you can use to commit or rollback.
func (a *Adapter) BeginTransaction(ctx context.Context) (persist.TransactionContext, error) {
	// Start ArangoDB streaming transaction
	tx, err := a.db.BeginTransaction(ctx, arangodb.TransactionCollections{
		Write: []string{a.collectionName},
	}, nil)
	if err != nil {
		return nil, err
	}

	return &ArangoTransactionContext{
		tx:             tx,
		ctx:            ctx,
		adapter:        a,
		collectionName: a.collectionName,
	}, nil
}

// ArangoTransactionContext wraps an ArangoDB transaction for Casbin.
type ArangoTransactionContext struct {
	tx             arangodb.Transaction
	ctx            context.Context
	adapter        *Adapter
	collectionName string
	committed      bool
	rolledBack     bool
}

// Commit commits the database transaction.
func (atx *ArangoTransactionContext) Commit() error {
	if atx.committed || atx.rolledBack {
		return errors.New("transaction already finished")
	}

	err := atx.tx.Commit(atx.ctx, nil)
	if err == nil {
		atx.committed = true
	}
	return err
}

// Rollback rolls back the database transaction.
func (atx *ArangoTransactionContext) Rollback() error {
	if atx.committed || atx.rolledBack {
		return errors.New("transaction already finished")
	}

	err := atx.tx.Abort(atx.ctx, nil)
	if err == nil {
		atx.rolledBack = true
	}
	return err
}

// GetAdapter returns an adapter that uses this transaction.
// Any policies you add/remove through it will be part of the transaction.
func (atx *ArangoTransactionContext) GetAdapter() persist.Adapter {
	return &Adapter{
		client:         atx.adapter.client,
		db:             atx.adapter.db,
		collection:     atx.adapter.collection,
		databaseName:   atx.adapter.databaseName,
		collectionName: atx.collectionName,
		isFiltered:     atx.adapter.isFiltered,
		transaction:    atx.tx, // Use transaction
	}
}

// Preview checks which rules are valid for the model.
// Filters out rules that don't match, so you don't get partial load failures.
func (a *Adapter) Preview(rules *[]CasbinRule, model model.Model) error {
	j := 0
	for i, rule := range *rules {
		// Build policy array
		r := []string{rule.Ptype, rule.V0, rule.V1, rule.V2, rule.V3, rule.V4, rule.V5}

		// Trim trailing empty fields
		index := len(r) - 1
		for r[index] == "" {
			index--
		}
		p := r[:index+1]

		key := p[0]
		sec := key[:1]

		// Check if this policy is valid for the model
		ok, err := model.HasPolicyEx(sec, key, p[1:])
		if err != nil {
			return err
		}

		// Keep only valid rules
		if ok {
			(*rules)[j], (*rules)[i] = rule, (*rules)[j]
			j++
		}
	}

	// Truncate to valid rules only
	*rules = (*rules)[j:]
	return nil
}

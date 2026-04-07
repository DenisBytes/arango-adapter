// Copyright 2024 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package arangoadapter provides a Casbin adapter implementation for ArangoDB.
package arangoadapter

import (
	"context"
	"errors"
	"fmt"
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

// CasbinRule represents a single Casbin policy rule stored as an ArangoDB document.
type CasbinRule struct {
	Key   string `json:"_key,omitempty"`
	Ptype string `json:"ptype"`
	V0    string `json:"v0"`
	V1    string `json:"v1"`
	V2    string `json:"v2"`
	V3    string `json:"v3"`
	V4    string `json:"v4"`
	V5    string `json:"v5"`
}

// Filter defines the filtering criteria for loading policies.
// Each field accepts multiple values to match against.
type Filter struct {
	Ptype []string
	V0    []string
	V1    []string
	V2    []string
	V3    []string
	V4    []string
	V5    []string
}

// BatchFilter holds multiple filters for batch-filtered policy loading.
type BatchFilter struct {
	filters []Filter
}

// NewBatchFilter creates a BatchFilter from one or more Filter values.
func NewBatchFilter(filters ...Filter) *BatchFilter {
	return &BatchFilter{filters: filters}
}

// Adapter implements the Casbin persist.Adapter interface for ArangoDB.
// It supports filtered policies, batch operations, and streaming transactions.
type Adapter struct {
	client         arangodb.Client
	db             arangodb.Database
	collection     arangodb.Collection
	databaseName   string
	collectionName string
	isFiltered     bool
	transaction    arangodb.Transaction
	transactionMu  *sync.Mutex
}

// NewAdapter creates a new Adapter for ArangoDB and ensures the
// target database and collection exist, creating them if necessary.
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

// NewFilteredAdapter creates an Adapter with filtered policy loading enabled.
// Casbin will not automatically call LoadPolicy() for a filtered adapter.
func NewFilteredAdapter(opts ...Option) (*Adapter, error) {
	adapter, err := NewAdapter(opts...)
	if err != nil {
		return nil, err
	}
	adapter.isFiltered = true
	return adapter, nil
}

// NewAdapterFromClient creates an adapter from an existing ArangoDB client.
// It creates the database and collection if they don't already exist.
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

// getCollection returns a transaction-bound collection if a transaction is active,
// otherwise the default collection.
func (a *Adapter) getCollection(ctx context.Context) (arangodb.Collection, error) {
	if a.transaction != nil {
		return a.transaction.GetCollection(ctx, a.collectionName, nil)
	}
	return a.collection, nil
}

// queryDB executes an AQL query, routing through the active transaction if one exists.
func (a *Adapter) queryDB(ctx context.Context, query string, opts *arangodb.QueryOptions) (arangodb.Cursor, error) {
	if a.transaction != nil {
		if opts == nil {
			opts = &arangodb.QueryOptions{}
		}
		opts.TransactionID = string(a.transaction.ID())
	}
	return a.db.Query(ctx, query, opts)
}

func (a *Adapter) ensureDatabaseExists() error {
	ctx := context.Background()
	db, err := a.client.Database(ctx, a.databaseName)
	if err != nil {
		db, err = a.client.CreateDatabase(ctx, a.databaseName, nil)
		if err != nil {
			return err
		}
	}
	a.db = db
	return nil
}

func (a *Adapter) ensureCollectionExists() error {
	ctx := context.Background()
	col, err := a.db.Collection(ctx, a.collectionName)
	if err != nil {
		col, err = a.db.CreateCollection(ctx, a.collectionName, nil)
		if err != nil {
			return err
		}
	}
	a.collection = col
	return nil
}

func loadPolicyLine(line CasbinRule, model model.Model) error {
	if line.Ptype == "" {
		return nil
	}

	p := []string{line.Ptype, line.V0, line.V1, line.V2, line.V3, line.V4, line.V5}

	// Trim trailing empty fields
	index := len(p) - 1
	for p[index] == "" {
		index--
	}
	p = p[:index+1]

	return persist.LoadPolicyArray(p, model)
}

// LoadPolicy loads all policy rules from the database.
func (a *Adapter) LoadPolicy(model model.Model) error {
	return a.LoadPolicyCtx(context.Background(), model)
}

// LoadPolicyCtx loads all policy rules from the database with context support.
func (a *Adapter) LoadPolicyCtx(ctx context.Context, model model.Model) error {
	query := "FOR doc IN @@collection RETURN doc"
	bindVars := map[string]interface{}{
		"@collection": a.collectionName,
	}

	cursor, err := a.queryDB(ctx, query, &arangodb.QueryOptions{
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

// LoadFilteredPolicy loads only policy rules that match the filter.
func (a *Adapter) LoadFilteredPolicy(model model.Model, filter interface{}) error {
	return a.LoadFilteredPolicyCtx(context.Background(), model, filter)
}

// LoadFilteredPolicyCtx loads filtered policy rules with context support.
func (a *Adapter) LoadFilteredPolicyCtx(ctx context.Context, model model.Model, filter interface{}) error {
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
		return fmt.Errorf("unsupported filter type: %T", filter)
	}

	if len(filters) == 0 {
		return a.LoadPolicyCtx(ctx, model)
	}

	for _, f := range filters {
		query := "FOR doc IN @@collection"
		bindVars := map[string]interface{}{
			"@collection": a.collectionName,
		}

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

		if len(conditions) > 0 {
			query += " FILTER " + strings.Join(conditions, " AND ")
		}
		query += " RETURN doc"

		cursor, err := a.queryDB(ctx, query, &arangodb.QueryOptions{
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

// SavePolicy saves all policy rules to the database.
func (a *Adapter) SavePolicy(model model.Model) error {
	return a.SavePolicyCtx(context.Background(), model)
}

// SavePolicyCtx clears the collection and writes every rule from the model.
// WARNING: this truncates the collection before writing.
func (a *Adapter) SavePolicyCtx(ctx context.Context, model model.Model) error {
	const batchSize = 1000

	col, err := a.getCollection(ctx)
	if err != nil {
		return err
	}

	err = col.Truncate(ctx)
	if err != nil {
		return err
	}

	var batch []CasbinRule

	flushBatch := func() error {
		if len(batch) == 0 {
			return nil
		}
		_, err := col.CreateDocuments(ctx, batch)
		if err != nil {
			return err
		}
		batch = batch[:0]
		return nil
	}

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

	return flushBatch()
}

func (a *Adapter) savePolicyLine(ptype string, rule []string) CasbinRule {
	line := CasbinRule{
		Ptype: ptype,
	}

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

// AddPolicy adds a policy rule to the storage.
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	return a.AddPolicyCtx(context.Background(), sec, ptype, rule)
}

// AddPolicyCtx adds a policy rule to the storage with context support.
func (a *Adapter) AddPolicyCtx(ctx context.Context, sec string, ptype string, rule []string) error {
	col, err := a.getCollection(ctx)
	if err != nil {
		return err
	}
	line := a.savePolicyLine(ptype, rule)
	_, err = col.CreateDocument(ctx, line)
	return err
}

// RemovePolicy removes a policy rule from the storage.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	return a.RemovePolicyCtx(context.Background(), sec, ptype, rule)
}

// RemovePolicyCtx removes a policy rule from the storage with context support.
func (a *Adapter) RemovePolicyCtx(ctx context.Context, sec string, ptype string, rule []string) error {
	line := a.savePolicyLine(ptype, rule)
	query := "FOR doc IN @@collection FILTER doc.ptype == @ptype"
	bindVars := map[string]interface{}{
		"@collection": a.collectionName,
		"ptype":       line.Ptype,
	}

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

	_, err := a.queryDB(ctx, query, &arangodb.QueryOptions{
		BindVars: bindVars,
	})
	return err
}

// AddPolicies adds multiple policy rules to the storage.
func (a *Adapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	return a.AddPoliciesCtx(context.Background(), sec, ptype, rules)
}

// AddPoliciesCtx adds multiple policy rules to the storage with context support.
func (a *Adapter) AddPoliciesCtx(ctx context.Context, sec string, ptype string, rules [][]string) error {
	col, err := a.getCollection(ctx)
	if err != nil {
		return err
	}
	var lines []CasbinRule
	for _, rule := range rules {
		lines = append(lines, a.savePolicyLine(ptype, rule))
	}
	_, err = col.CreateDocuments(ctx, lines)
	return err
}

// RemovePolicies removes multiple policy rules from the storage.
func (a *Adapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	return a.RemovePoliciesCtx(context.Background(), sec, ptype, rules)
}

// RemovePoliciesCtx removes multiple policy rules from the storage with context support.
func (a *Adapter) RemovePoliciesCtx(ctx context.Context, sec string, ptype string, rules [][]string) error {
	if len(rules) == 0 {
		return nil
	}

	query := "FOR doc IN @@collection FILTER doc.ptype == @ptype AND ("
	bindVars := map[string]interface{}{
		"@collection": a.collectionName,
		"ptype":       ptype,
	}

	var ruleConditions []string
	for i, rule := range rules {
		line := a.savePolicyLine(ptype, rule)

		fields := []string{line.V0, line.V1, line.V2, line.V3, line.V4, line.V5}
		fieldConditions := make([]string, 6)
		for f, val := range fields {
			key := fmt.Sprintf("r%d_v%d", i, f)
			fieldConditions[f] = fmt.Sprintf("doc.v%d == @%s", f, key)
			bindVars[key] = val
		}
		ruleConditions = append(ruleConditions, "("+strings.Join(fieldConditions, " && ")+")")
	}

	query += strings.Join(ruleConditions, " OR ")
	query += ") REMOVE doc IN @@collection"

	_, err := a.queryDB(ctx, query, &arangodb.QueryOptions{
		BindVars: bindVars,
	})
	return err
}

// RemoveFilteredPolicy removes policy rules that match the filter.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return a.RemoveFilteredPolicyCtx(context.Background(), sec, ptype, fieldIndex, fieldValues...)
}

// RemoveFilteredPolicyCtx removes filtered policy rules with context support.
func (a *Adapter) RemoveFilteredPolicyCtx(ctx context.Context, sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	query := "FOR doc IN @@collection FILTER doc.ptype == @ptype"
	bindVars := map[string]interface{}{
		"@collection": a.collectionName,
		"ptype":       ptype,
	}

	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) && fieldValues[0-fieldIndex] != "" {
		query += " && doc.v0 == @v0"
		bindVars["v0"] = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) && fieldValues[1-fieldIndex] != "" {
		query += " && doc.v1 == @v1"
		bindVars["v1"] = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) && fieldValues[2-fieldIndex] != "" {
		query += " && doc.v2 == @v2"
		bindVars["v2"] = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) && fieldValues[3-fieldIndex] != "" {
		query += " && doc.v3 == @v3"
		bindVars["v3"] = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) && fieldValues[4-fieldIndex] != "" {
		query += " && doc.v4 == @v4"
		bindVars["v4"] = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) && fieldValues[5-fieldIndex] != "" {
		query += " && doc.v5 == @v5"
		bindVars["v5"] = fieldValues[5-fieldIndex]
	}

	// Guard: if no field conditions were added, all fieldValues were empty.
	// Refuse to delete all rules of a ptype — caller likely has a bug.
	if !strings.Contains(query, "@v") {
		return fmt.Errorf("RemoveFilteredPolicy called with no effective field filters; refusing broad deletion")
	}

	query += " REMOVE doc IN @@collection"

	_, err := a.queryDB(ctx, query, &arangodb.QueryOptions{
		BindVars: bindVars,
	})
	return err
}

// UpdatePolicy updates a policy rule from the storage.
func (a *Adapter) UpdatePolicy(sec string, ptype string, oldRule, newPolicy []string) error {
	return a.UpdatePolicyCtx(context.Background(), sec, ptype, oldRule, newPolicy)
}

// UpdatePolicyCtx replaces the first rule matching oldRule with newPolicy.
func (a *Adapter) UpdatePolicyCtx(ctx context.Context, sec string, ptype string, oldRule, newPolicy []string) error {
	oldLine := a.savePolicyLine(ptype, oldRule)
	newLine := a.savePolicyLine(ptype, newPolicy)

	query := "FOR doc IN @@collection FILTER doc.ptype == @ptype"
	bindVars := map[string]interface{}{
		"@collection": a.collectionName,
		"ptype":       oldLine.Ptype,
	}

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

	query += " UPDATE doc WITH { ptype: @new_ptype, v0: @new_v0, v1: @new_v1, v2: @new_v2, v3: @new_v3, v4: @new_v4, v5: @new_v5 } IN @@collection"

	bindVars["new_ptype"] = newLine.Ptype
	bindVars["new_v0"] = newLine.V0
	bindVars["new_v1"] = newLine.V1
	bindVars["new_v2"] = newLine.V2
	bindVars["new_v3"] = newLine.V3
	bindVars["new_v4"] = newLine.V4
	bindVars["new_v5"] = newLine.V5

	_, err := a.queryDB(ctx, query, &arangodb.QueryOptions{
		BindVars: bindVars,
	})
	return err
}

// UpdatePolicies updates multiple policy rules in the storage.
func (a *Adapter) UpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) error {
	return a.UpdatePoliciesCtx(context.Background(), sec, ptype, oldRules, newRules)
}

// UpdatePoliciesCtx updates multiple policy rules in the storage with context support.
func (a *Adapter) UpdatePoliciesCtx(ctx context.Context, sec string, ptype string, oldRules, newRules [][]string) error {
	if len(oldRules) != len(newRules) {
		return errors.New("oldRules and newRules must have the same length")
	}
	for i, oldRule := range oldRules {
		err := a.UpdatePolicyCtx(ctx, sec, ptype, oldRule, newRules[i])
		if err != nil {
			return err
		}
	}
	return nil
}

// UpdateFilteredPolicies deletes old rules matching the filter and adds new ones.
func (a *Adapter) UpdateFilteredPolicies(sec string, ptype string, newPolicies [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	return a.UpdateFilteredPoliciesCtx(context.Background(), sec, ptype, newPolicies, fieldIndex, fieldValues...)
}

// UpdateFilteredPoliciesCtx atomically removes rules matching the filter
// and inserts newPolicies. Returns the old rules that were removed.
func (a *Adapter) UpdateFilteredPoliciesCtx(ctx context.Context, sec string, ptype string, newPolicies [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	query := "FOR doc IN @@collection FILTER doc.ptype == @ptype"
	bindVars := map[string]interface{}{
		"@collection": a.collectionName,
		"ptype":       ptype,
	}

	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) && fieldValues[0-fieldIndex] != "" {
		query += " && doc.v0 == @v0"
		bindVars["v0"] = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) && fieldValues[1-fieldIndex] != "" {
		query += " && doc.v1 == @v1"
		bindVars["v1"] = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) && fieldValues[2-fieldIndex] != "" {
		query += " && doc.v2 == @v2"
		bindVars["v2"] = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) && fieldValues[3-fieldIndex] != "" {
		query += " && doc.v3 == @v3"
		bindVars["v3"] = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) && fieldValues[4-fieldIndex] != "" {
		query += " && doc.v4 == @v4"
		bindVars["v4"] = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) && fieldValues[5-fieldIndex] != "" {
		query += " && doc.v5 == @v5"
		bindVars["v5"] = fieldValues[5-fieldIndex]
	}

	// Single-pass: remove matching docs and return the old values
	query += " REMOVE doc IN @@collection RETURN OLD"

	cursor, err := a.queryDB(ctx, query, &arangodb.QueryOptions{
		BindVars: bindVars,
	})
	if err != nil {
		return nil, err
	}

	oldPolicies := make([][]string, 0)
	for cursor.HasMore() {
		var rule CasbinRule
		_, err := cursor.ReadDocument(ctx, &rule)
		if err != nil {
			_ = cursor.Close()
			return nil, err
		}
		policy := []string{rule.V0, rule.V1, rule.V2, rule.V3, rule.V4, rule.V5}
		i := len(policy) - 1
		for i >= 0 && policy[i] == "" {
			i--
		}
		oldPolicies = append(oldPolicies, policy[:i+1])
	}
	_ = cursor.Close()

	// Add new policies in batch
	if len(newPolicies) > 0 {
		if err := a.AddPoliciesCtx(ctx, sec, ptype, newPolicies); err != nil {
			return nil, err
		}
	}

	return oldPolicies, nil
}

// Close is a no-op as the ArangoDB driver manages connections internally.
func (a *Adapter) Close() error {
	return nil
}

// Copy creates a shallow copy of the adapter.
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

// Transaction executes fc within a streaming ArangoDB transaction.
// On success it commits; on error it aborts and reloads the model.
// The enforcer's adapter is swapped to a transaction-bound copy for the
// duration of fc and restored afterward regardless of outcome.
func (a *Adapter) Transaction(e casbin.IEnforcer, fc func(casbin.IEnforcer) error) error {
	a.transactionMu.Lock()
	defer a.transactionMu.Unlock()

	originalAdapter := a.Copy()
	ctx := context.Background()

	tx, err := a.db.BeginTransaction(ctx, arangodb.TransactionCollections{
		Write: []string{a.collectionName},
	}, nil)
	if err != nil {
		return err
	}

	txAdapter := &Adapter{
		client:         a.client,
		db:             a.db,
		collection:     a.collection,
		databaseName:   a.databaseName,
		collectionName: a.collectionName,
		isFiltered:     a.isFiltered,
		transactionMu:  a.transactionMu,
		transaction:    tx,
	}

	e.SetAdapter(txAdapter)
	err = fc(e)
	e.SetAdapter(originalAdapter)

	if err != nil {
		if abortErr := tx.Abort(ctx, nil); abortErr != nil {
			return fmt.Errorf("transaction abort failed: %w (original error: %v)", abortErr, err)
		}
		if loadErr := e.LoadPolicy(); loadErr != nil {
			return fmt.Errorf("policy reload failed after rollback: %w (original error: %v)", loadErr, err)
		}
		return err
	}

	if commitErr := tx.Commit(ctx, nil); commitErr != nil {
		return commitErr
	}

	return nil
}

// BeginTransaction starts a new database transaction.
func (a *Adapter) BeginTransaction(ctx context.Context) (persist.TransactionContext, error) {
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

// ArangoTransactionContext implements persist.TransactionContext for ArangoDB.
type ArangoTransactionContext struct {
	tx             arangodb.Transaction
	ctx            context.Context
	adapter        *Adapter
	collectionName string
	committed      bool
	rolledBack     bool
}

// Commit commits the transaction.
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

// Rollback aborts the transaction.
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

// GetAdapter returns an adapter bound to this transaction.
func (atx *ArangoTransactionContext) GetAdapter() persist.Adapter {
	return &Adapter{
		client:         atx.adapter.client,
		db:             atx.adapter.db,
		collection:     atx.adapter.collection,
		databaseName:   atx.adapter.databaseName,
		collectionName: atx.collectionName,
		isFiltered:     atx.adapter.isFiltered,
		transaction:    atx.tx,
		transactionMu:  atx.adapter.transactionMu,
	}
}

// Preview removes rules from the slice that already exist in the model,
// leaving only rules that would be new additions.
func (a *Adapter) Preview(rules *[]CasbinRule, model model.Model) error {
	j := 0
	for i, rule := range *rules {
		r := []string{rule.Ptype, rule.V0, rule.V1, rule.V2, rule.V3, rule.V4, rule.V5}

		index := len(r) - 1
		for r[index] == "" {
			index--
		}
		p := r[:index+1]

		key := p[0]
		sec := key[:1]

		ok, err := model.HasPolicyEx(sec, key, p[1:])
		if err != nil {
			return err
		}

		if ok {
			(*rules)[j], (*rules)[i] = rule, (*rules)[j]
			j++
		}
	}

	*rules = (*rules)[j:]
	return nil
}

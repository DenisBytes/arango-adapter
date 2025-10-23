// Package arangoadapter provides a Casbin adapter for ArangoDB.
// It allows you to persist authorization policies in ArangoDB instead of local files.
package arangoadapter

import (
	"context"
	"sync"

	"github.com/arangodb/go-driver/v2/arangodb"
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

// Adapter is the main struct that connects Casbin to ArangoDB.
// It handles all the CRUD operations for policy rules.
type Adapter struct {
	client         arangodb.Client
	db             arangodb.Database
	collection     arangodb.Collection
	databaseName   string
	collectionName string
	isFiltered     bool
	transactionMu  *sync.Mutex
	muInitialize   sync.Once
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
	var p []string

	if line.Ptype == "" {
		return nil
	}

	p = append(p, line.V0, line.V1, line.V2, line.V3, line.V4, line.V5)

	// Trim trailing empty fields since Casbin doesn't need them
	index := len(p) - 1
	for p[index] == "" {
		index--
	}
	p = p[:index+1]

	// Figure out which section this rule belongs to ("p" or "g")
	section := line.Ptype[:1]

	// Let the model handle adding this policy
	err := persist.LoadPolicyArray(p, model[section][line.Ptype])
	return err
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
	defer cursor.Close()

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

// SavePolicy saves all policies from the Casbin model back to the database.
// Warning: This wipes out the entire collection and replaces it with the current policy set.
func (a *Adapter) SavePolicy(model model.Model) error {
	return a.SavePolicyCtx(context.Background(), model)
}

// SavePolicyCtx is like SavePolicy but with context support.
func (a *Adapter) SavePolicyCtx(ctx context.Context, model model.Model) error {
	var rules []CasbinRule

	// Collect all the "p" type rules (permissions)
	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			rules = append(rules, a.savePolicyLine(ptype, rule))
		}
	}

	// Collect all the "g" type rules (roles/groups)
	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			rules = append(rules, a.savePolicyLine(ptype, rule))
		}
	}

	// Clear everything out first
	err := a.collection.Truncate(ctx)
	if err != nil {
		return err
	}

	// Then insert all the rules
	_, err = a.collection.CreateDocuments(ctx, rules)
	return err
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

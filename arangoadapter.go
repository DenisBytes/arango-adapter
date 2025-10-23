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

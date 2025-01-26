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

type Filter struct {
	Ptype []string
	V0    []string
	V1    []string
	V2    []string
	V3    []string
	V4    []string
	V5    []string
}

type BatchFilter struct {
	filters []Filter
}

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

func NewAdapter(client arangodb.Client, databaseName string, collectionName string) (*Adapter, error) {
	a := &Adapter{
		client:         client,
		databaseName:   databaseName,
		collectionName: collectionName,
		transactionMu:  &sync.Mutex{},
	}

	err := a.Open()
	if err != nil {
		return nil, err
	}

	return a, nil
}

func (a *Adapter) Open() error {
	ctx := context.Background()

	db, err := a.client.Database(ctx, a.databaseName)
	if err != nil {
		db, err = a.client.CreateDatabase(ctx, a.databaseName, nil)
		if err != nil {
			return err
		}
	}
	a.db = db

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
	var p = []string{line.Ptype,
		line.V0, line.V1, line.V2,
		line.V3, line.V4, line.V5}

	index := len(p) - 1
	for p[index] == "" {
		index--
	}
	index += 1
	p = p[:index]
	err := persist.LoadPolicyArray(p, model)
	if err != nil {
		return err
	}
	return nil
}

func (a *Adapter) LoadPolicy(model model.Model) error {
	return a.LoadPolicyCtx(context.Background(), model)
}

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

func (a *Adapter) SavePolicy(model model.Model) error {
	return a.SavePolicyCtx(context.Background(), model)
}

func (a *Adapter) SavePolicyCtx(ctx context.Context, model model.Model) error {
	var rules []CasbinRule

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			rules = append(rules, a.savePolicyLine(ptype, rule))
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			rules = append(rules, a.savePolicyLine(ptype, rule))
		}
	}

	err := a.collection.Truncate(ctx)
	if err != nil {
		return err
	}

	_, err = a.collection.CreateDocuments(ctx, rules)
	return err
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

func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	return a.AddPolicyCtx(context.Background(), sec, ptype, rule)
}

func (a *Adapter) AddPolicyCtx(ctx context.Context, sec string, ptype string, rule []string) error {
	line := a.savePolicyLine(ptype, rule)
	_, err := a.collection.CreateDocument(ctx, line)
	return err
}

func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	return a.RemovePolicyCtx(context.Background(), sec, ptype, rule)
}

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

	_, err := a.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: bindVars,
	})
	return err
}

func (a *Adapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	var lines []CasbinRule
	for _, rule := range rules {
		lines = append(lines, a.savePolicyLine(ptype, rule))
	}
	_, err := a.collection.CreateDocuments(context.Background(), lines)
	return err
}

func (a *Adapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	for _, rule := range rules {
		err := a.RemovePolicy(sec, ptype, rule)
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return a.RemoveFilteredPolicyCtx(context.Background(), sec, ptype, fieldIndex, fieldValues...)
}

func (a *Adapter) RemoveFilteredPolicyCtx(ctx context.Context, sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	query := "FOR doc IN @@collection FILTER doc.ptype == @ptype"
	bindVars := map[string]interface{}{
		"@collection": a.collectionName,
		"ptype":       ptype,
	}

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

func (a *Adapter) UpdatePolicy(sec string, ptype string, oldRule, newPolicy []string) error {
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

	_, err := a.db.Query(context.Background(), query, &arangodb.QueryOptions{
		BindVars: bindVars,
	})
	return err
}

func (a *Adapter) UpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) error {
	for i, oldRule := range oldRules {
		err := a.UpdatePolicy(sec, ptype, oldRule, newRules[i])
		if err != nil {
			return err
		}
	}
	return nil
}

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

package graphql_federation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/ast"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/astparser"

	"github.com/TykTechnologies/tyk/apidef"
)

// graphqlProbeTimeout bounds the API-load-time probe per upstream.
const graphqlProbeTimeout = 5 * time.Second

// graphqlEntityResolver resolves entities by querying a GraphQL upstream.
//
// It picks one of three strategies at construction time and sticks to it:
//
//  1. operationOverride: caller supplied an explicit operation in the
//     data-source config. The resolver renders Operation/Variables as Go
//     templates over the representation and POSTs the result.
//  2. federationPassthrough: the upstream answered `{ _service { sdl } }` —
//     it's a federation subgraph (or supergraph). We forward an
//     `_entities(representations: [...])` query verbatim, one rep per call,
//     and return `data._entities[0]`.
//  3. generatedLookup: the upstream is plain GraphQL (Hasura, PostGraphile,
//     hand-written Apollo Server). We discovered a unique Query field that
//     returns the entity type and accepts the @key field as a single
//     argument. We issue `query($k: ArgT!) { field(arg: $k) { ...fields } }`
//     and return `data.<field>`.
type graphqlEntityResolver struct {
	URL     string
	Method  string
	Headers map[string]string
	Client  *http.Client

	strategy graphqlResolverStrategy

	// operationOverride
	operationTpl *template.Template
	variablesTpl *template.Template

	// federationPassthrough / generatedLookup share these
	entityTypeName string
	keyFieldName   string

	// federationPassthrough
	federationQuery string

	// generatedLookup
	lookupQuery   string
	lookupArgName string
}

type graphqlResolverStrategy int

const (
	graphqlStrategyOperationOverride graphqlResolverStrategy = iota
	graphqlStrategyFederationPassthrough
	graphqlStrategyGeneratedLookup
)

func (r *graphqlEntityResolver) resolve(ctx context.Context, representation map[string]any) (map[string]any, error) {
	switch r.strategy {
	case graphqlStrategyOperationOverride:
		return r.resolveOperationOverride(ctx, representation)
	case graphqlStrategyFederationPassthrough:
		return r.resolveFederation(ctx, representation)
	case graphqlStrategyGeneratedLookup:
		return r.resolveGeneratedLookup(ctx, representation)
	default:
		return nil, fmt.Errorf("graphqlEntityResolver: unknown strategy")
	}
}

func (r *graphqlEntityResolver) resolveOperationOverride(ctx context.Context, representation map[string]any) (map[string]any, error) {
	tplCtx := map[string]any{"object": representation}

	var queryBuf bytes.Buffer
	if err := r.operationTpl.Execute(&queryBuf, tplCtx); err != nil {
		return nil, fmt.Errorf("render operation template: %w", err)
	}

	var variables any
	if r.variablesTpl != nil {
		var varBuf bytes.Buffer
		if err := r.variablesTpl.Execute(&varBuf, tplCtx); err != nil {
			return nil, fmt.Errorf("render variables template: %w", err)
		}
		raw := bytes.TrimSpace(varBuf.Bytes())
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &variables); err != nil {
				return nil, fmt.Errorf("parse rendered variables: %w", err)
			}
		}
	}

	resp, err := r.postGraphQL(ctx, queryBuf.String(), variables)
	if err != nil {
		return nil, err
	}
	if resp.Data == nil {
		return nil, fmt.Errorf("upstream returned no data")
	}
	// The customer's operation is expected to project the entity; if there's
	// exactly one top-level field, unwrap it. Otherwise return the data map
	// as-is and let the engine project.
	if len(resp.Data) == 1 {
		for _, v := range resp.Data {
			if obj, ok := v.(map[string]any); ok {
				out := mergeRepresentation(obj, representation)
				return out, nil
			}
		}
	}
	return mergeRepresentation(resp.Data, representation), nil
}

func (r *graphqlEntityResolver) resolveFederation(ctx context.Context, representation map[string]any) (map[string]any, error) {
	variables := map[string]any{
		"r": []any{representation},
	}
	resp, err := r.postGraphQL(ctx, r.federationQuery, variables)
	if err != nil {
		return nil, err
	}
	if resp.Data == nil {
		return nil, fmt.Errorf("upstream returned no data for _entities")
	}
	rawEntities, ok := resp.Data["_entities"]
	if !ok {
		return nil, fmt.Errorf("upstream response missing _entities")
	}
	entities, ok := rawEntities.([]any)
	if !ok || len(entities) == 0 {
		return nil, fmt.Errorf("upstream _entities is not a non-empty array")
	}
	if entities[0] == nil {
		return nil, fmt.Errorf("upstream returned null at _entities[0]")
	}
	obj, ok := entities[0].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("upstream _entities[0] is not an object")
	}
	return mergeRepresentation(obj, representation), nil
}

func (r *graphqlEntityResolver) resolveGeneratedLookup(ctx context.Context, representation map[string]any) (map[string]any, error) {
	keyVal, ok := representation[r.keyFieldName]
	if !ok {
		return nil, fmt.Errorf("representation missing key field %q", r.keyFieldName)
	}
	variables := map[string]any{"k": keyVal}
	resp, err := r.postGraphQL(ctx, r.lookupQuery, variables)
	if err != nil {
		return nil, err
	}
	if resp.Data == nil {
		return nil, fmt.Errorf("upstream returned no data")
	}
	// The lookup query has exactly one selection: find it (we don't hard-code
	// the field name because Go map iteration is fine when there's one key).
	var inner any
	for _, v := range resp.Data {
		inner = v
		break
	}
	if inner == nil {
		return nil, fmt.Errorf("upstream returned null for entity lookup")
	}
	obj, ok := inner.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("upstream lookup result is not an object")
	}
	return mergeRepresentation(obj, representation), nil
}

// mergeRepresentation copies the representation's __typename onto the resolved
// entity (the entitiesDataSource.Load loop also sets __typename, but doing it
// here keeps the resolver self-consistent for callers that bypass Load).
func mergeRepresentation(entity, representation map[string]any) map[string]any {
	if entity == nil {
		entity = map[string]any{}
	}
	if t, ok := representation["__typename"]; ok {
		if _, exists := entity["__typename"]; !exists {
			entity["__typename"] = t
		}
	}
	return entity
}

// graphqlResponse is the standard `{data, errors}` shape.
type graphqlResponse struct {
	Data   map[string]any   `json:"data"`
	Errors []map[string]any `json:"errors"`
}

func (r *graphqlEntityResolver) postGraphQL(ctx context.Context, query string, variables any) (*graphqlResponse, error) {
	payload := map[string]any{"query": query}
	if variables != nil {
		payload["variables"] = variables
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal graphql body: %w", err)
	}
	method := r.Method
	if method == "" {
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, r.URL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build graphql request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}
	client := r.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("graphql upstream call: %w", err)
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read graphql response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("graphql upstream returned status %d: %s", resp.StatusCode, string(respBytes))
	}
	var out graphqlResponse
	if err := json.Unmarshal(respBytes, &out); err != nil {
		return nil, fmt.Errorf("parse graphql response: %w", err)
	}
	if len(out.Errors) > 0 {
		// First error wins for diagnostics; keep it concise.
		msg, _ := out.Errors[0]["message"].(string)
		if msg == "" {
			msg = "unknown error"
		}
		return nil, fmt.Errorf("graphql upstream errored: %s", msg)
	}
	return &out, nil
}

// buildGraphQLEntityResolver constructs a graphqlEntityResolver, picking a
// strategy at construction time. The customer SDL is parsed to derive the
// selection set we send upstream; the upstream is probed once to decide
// between federation pass-through and generated-lookup.
//
// Note: we select every field of the entity declared in the customer's SDL.
// That's an intentional overfetch — the engine projects what the client asked
// for, and probing per-request would be too costly.
func buildGraphQLEntityResolver(
	cfg apidef.GraphQLEngineDataSourceConfigGraphQL,
	entityTypeName string,
	customerSchemaSDL string,
	httpClient *http.Client,
) (*graphqlEntityResolver, error) {
	entityFields, keyField, err := entitySelectionInfo(customerSchemaSDL, entityTypeName)
	if err != nil {
		return nil, err
	}

	resolver := &graphqlEntityResolver{
		URL:            cfg.URL,
		Method:         cfg.Method,
		Headers:        cfg.Headers,
		Client:         httpClient,
		entityTypeName: entityTypeName,
		keyFieldName:   keyField,
	}

	// 1) explicit-operation override.
	if cfg.HasOperation && strings.TrimSpace(cfg.Operation) != "" {
		opTpl, err := template.New("graphql_op").Option("missingkey=error").Parse(cfg.Operation)
		if err != nil {
			return nil, fmt.Errorf("parse operation template: %w", err)
		}
		resolver.operationTpl = opTpl
		if len(cfg.Variables) > 0 && !isJSONNullOrEmpty(cfg.Variables) {
			varTpl, err := template.New("graphql_vars").Option("missingkey=error").Parse(string(cfg.Variables))
			if err != nil {
				return nil, fmt.Errorf("parse variables template: %w", err)
			}
			resolver.variablesTpl = varTpl
		}
		resolver.strategy = graphqlStrategyOperationOverride
		return resolver, nil
	}

	// 2) probe.
	probeClient := httpClient
	if probeClient == nil {
		probeClient = &http.Client{Timeout: graphqlProbeTimeout}
	} else {
		// Keep the caller's transport, but cap the probe.
		shallow := *probeClient
		if shallow.Timeout == 0 || shallow.Timeout > graphqlProbeTimeout {
			shallow.Timeout = graphqlProbeTimeout
		}
		probeClient = &shallow
	}
	tmpResolver := *resolver
	tmpResolver.Client = probeClient

	if sdl, ok := probeFederationSDL(&tmpResolver); ok && sdl != "" {
		resolver.strategy = graphqlStrategyFederationPassthrough
		resolver.federationQuery = buildFederationEntitiesQuery(entityTypeName, entityFields)
		return resolver, nil
	}

	// 3) introspect and pick a generated lookup.
	introspection, err := probeIntrospection(&tmpResolver)
	if err != nil {
		return nil, fmt.Errorf(
			"graphql upstream for %s: probe failed (neither _service { sdl } nor introspection responded usefully); "+
				"set has_operation=true with an explicit operation in the data-source config to override: %w",
			entityTypeName, err,
		)
	}
	field, argName, argType, perr := pickLookupField(introspection, entityTypeName, keyField)
	if perr != nil {
		return nil, fmt.Errorf(
			"graphql upstream for %s: %s; set has_operation=true with an explicit operation in the data-source config to override",
			entityTypeName, perr.Error(),
		)
	}
	resolver.strategy = graphqlStrategyGeneratedLookup
	resolver.lookupArgName = argName
	resolver.lookupQuery = buildGeneratedLookupQuery(field, argName, argType, entityTypeName, entityFields)
	return resolver, nil
}

func isJSONNullOrEmpty(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace([]byte(raw))
	if len(trimmed) == 0 {
		return true
	}
	return string(trimmed) == "null"
}

// entitySelectionInfo returns the list of field names declared on the entity
// type in the customer's SDL plus the @key field (single-key entities only —
// composite keys aren't handled here, matching the REST resolver's scope).
func entitySelectionInfo(sdl, entityTypeName string) ([]string, string, error) {
	doc, report := astparser.ParseGraphqlDocumentString(sdl)
	if report.HasErrors() {
		return nil, "", report
	}
	var fields []string
	var keyField string
	collectKey := func(fieldsArg string) {
		// `@key(fields: "id")` — composite keys come through as
		// `@key(fields: "id name")`; we only handle the single-field shape.
		f := strings.TrimSpace(fieldsArg)
		if !strings.ContainsAny(f, " \t\n") {
			keyField = f
		}
	}
	walk := func(name string, hasDirectives bool, dirRefs []int, hasFields bool, fieldRefs []int) bool {
		if name != entityTypeName {
			return false
		}
		if hasDirectives {
			for _, dRef := range dirRefs {
				if doc.DirectiveNameString(dRef) != "key" {
					continue
				}
				if val, ok := doc.DirectiveArgumentValueByName(dRef, []byte("fields")); ok {
					if val.Kind == ast.ValueKindString {
						collectKey(doc.StringValueContentString(val.Ref))
					}
				}
			}
		}
		if hasFields {
			for _, fRef := range fieldRefs {
				fields = append(fields, doc.FieldDefinitionNameString(fRef))
			}
		}
		return true
	}
	for i := range doc.ObjectTypeDefinitions {
		def := doc.ObjectTypeDefinitions[i]
		dirRefs := []int{}
		if def.HasDirectives {
			dirRefs = def.Directives.Refs
		}
		fieldRefs := []int{}
		if def.HasFieldDefinitions {
			fieldRefs = def.FieldsDefinition.Refs
		}
		walk(doc.ObjectTypeDefinitionNameString(i), def.HasDirectives, dirRefs, def.HasFieldDefinitions, fieldRefs)
	}
	for i := range doc.ObjectTypeExtensions {
		ext := doc.ObjectTypeExtensions[i]
		dirRefs := []int{}
		if ext.HasDirectives {
			dirRefs = ext.Directives.Refs
		}
		fieldRefs := []int{}
		if ext.HasFieldDefinitions {
			fieldRefs = ext.FieldsDefinition.Refs
		}
		walk(doc.ObjectTypeExtensionNameString(i), ext.HasDirectives, dirRefs, ext.HasFieldDefinitions, fieldRefs)
	}
	if len(fields) == 0 {
		return nil, "", fmt.Errorf("no fields declared for entity type %q in SDL", entityTypeName)
	}
	if keyField == "" {
		return nil, "", fmt.Errorf("entity type %q has no single-field @key directive (composite keys aren't supported by the auto-detect path)", entityTypeName)
	}
	// Stable order, but keep declaration order — we sort once for determinism
	// in tests when SDL parsing reorders refs.
	sort.SliceStable(fields, func(i, j int) bool { return false })
	return fields, keyField, nil
}

// probeFederationSDL issues `query { _service { sdl } }` and returns the SDL
// string if the upstream answers it. Any error / non-string SDL → not a
// federation subgraph.
func probeFederationSDL(r *graphqlEntityResolver) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), graphqlProbeTimeout)
	defer cancel()
	resp, err := r.postGraphQL(ctx, `query { _service { sdl } }`, nil)
	if err != nil {
		return "", false
	}
	if resp.Data == nil {
		return "", false
	}
	svc, ok := resp.Data["_service"].(map[string]any)
	if !ok {
		return "", false
	}
	sdl, ok := svc["sdl"].(string)
	if !ok {
		return "", false
	}
	return sdl, true
}

// minimalIntrospectionQuery: only the bits we need to find Query fields, their
// return type (unwrapped through NonNull/List), and their single-arg shape.
const minimalIntrospectionQuery = `query Introspect {
  __schema {
    queryType { name }
    types {
      kind
      name
      fields {
        name
        type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
        args {
          name
          type { kind name ofType { kind name ofType { kind name } } }
        }
      }
    }
  }
}`

type introspectionResult struct {
	queryTypeName string
	queryFields   []introspectionField
}

type introspectionField struct {
	Name       string
	ReturnType introspectionTypeRef
	Args       []introspectionArg
}

type introspectionArg struct {
	Name string
	Type introspectionTypeRef
}

type introspectionTypeRef struct {
	Kind   string
	Name   string
	OfType *introspectionTypeRef
}

func probeIntrospection(r *graphqlEntityResolver) (*introspectionResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), graphqlProbeTimeout)
	defer cancel()
	resp, err := r.postGraphQL(ctx, minimalIntrospectionQuery, nil)
	if err != nil {
		return nil, err
	}
	if resp.Data == nil {
		return nil, errors.New("introspection returned no data")
	}
	schema, ok := resp.Data["__schema"].(map[string]any)
	if !ok {
		return nil, errors.New("introspection response missing __schema")
	}
	queryTypeName := "Query"
	if qt, ok := schema["queryType"].(map[string]any); ok {
		if name, ok := qt["name"].(string); ok && name != "" {
			queryTypeName = name
		}
	}
	rawTypes, _ := schema["types"].([]any)
	out := &introspectionResult{queryTypeName: queryTypeName}
	for _, rawT := range rawTypes {
		t, ok := rawT.(map[string]any)
		if !ok {
			continue
		}
		name, _ := t["name"].(string)
		if name != queryTypeName {
			continue
		}
		rawFields, _ := t["fields"].([]any)
		for _, rawF := range rawFields {
			f, ok := rawF.(map[string]any)
			if !ok {
				continue
			}
			fName, _ := f["name"].(string)
			if fName == "" {
				continue
			}
			fld := introspectionField{
				Name:       fName,
				ReturnType: parseTypeRef(f["type"]),
			}
			rawArgs, _ := f["args"].([]any)
			for _, rawA := range rawArgs {
				a, ok := rawA.(map[string]any)
				if !ok {
					continue
				}
				aName, _ := a["name"].(string)
				if aName == "" {
					continue
				}
				fld.Args = append(fld.Args, introspectionArg{
					Name: aName,
					Type: parseTypeRef(a["type"]),
				})
			}
			out.queryFields = append(out.queryFields, fld)
		}
	}
	return out, nil
}

func parseTypeRef(raw any) introspectionTypeRef {
	m, ok := raw.(map[string]any)
	if !ok {
		return introspectionTypeRef{}
	}
	out := introspectionTypeRef{}
	if k, ok := m["kind"].(string); ok {
		out.Kind = k
	}
	if n, ok := m["name"].(string); ok {
		out.Name = n
	}
	if of, ok := m["ofType"]; ok && of != nil {
		inner := parseTypeRef(of)
		out.OfType = &inner
	}
	return out
}

// unwrapNamedType walks NonNull/List wrappers to the named (Object/Scalar)
// type underneath.
func unwrapNamedType(t introspectionTypeRef) introspectionTypeRef {
	cur := t
	for cur.Name == "" && cur.OfType != nil {
		cur = *cur.OfType
	}
	return cur
}

// isListType reports whether the type ref (or any wrapper above its named
// type) is a LIST. Used to exclude list-returning Query fields from
// auto-detection — entity lookups must return a single object.
func isListType(t introspectionTypeRef) bool {
	cur := t
	for cur.Name == "" && cur.OfType != nil {
		if cur.Kind == "LIST" {
			return true
		}
		cur = *cur.OfType
	}
	return cur.Kind == "LIST"
}

// renderTypeRef serializes a type ref back to GraphQL syntax (e.g. "ID!",
// "[String!]!"). Used to write the variable type into the generated query.
func renderTypeRef(t introspectionTypeRef) string {
	switch t.Kind {
	case "NON_NULL":
		if t.OfType != nil {
			return renderTypeRef(*t.OfType) + "!"
		}
		return ""
	case "LIST":
		if t.OfType != nil {
			return "[" + renderTypeRef(*t.OfType) + "]"
		}
		return "[]"
	default:
		return t.Name
	}
}

// pickLookupField finds the unique Query field that returns the given entity
// type and accepts a single argument matching the key field (by name) — or a
// single argument outright if its name doesn't match but it's the only option.
func pickLookupField(intro *introspectionResult, entityTypeName, keyField string) (field, argName string, argType introspectionTypeRef, err error) {
	type candidate struct {
		field   introspectionField
		argName string
		argType introspectionTypeRef
	}
	var byName []candidate
	var byShape []candidate
	for _, f := range intro.queryFields {
		// Skip list-returning fields — entity lookups must return a single
		// object. `[User!]!` would unwrap to `User` here and then fail at
		// resolve time when we cast the result to map[string]any.
		if isListType(f.ReturnType) {
			continue
		}
		ret := unwrapNamedType(f.ReturnType)
		if ret.Name != entityTypeName {
			continue
		}
		if len(f.Args) != 1 {
			continue
		}
		a := f.Args[0]
		c := candidate{field: f, argName: a.Name, argType: a.Type}
		if a.Name == keyField {
			byName = append(byName, c)
		}
		byShape = append(byShape, c)
	}
	if len(byName) == 1 {
		c := byName[0]
		return c.field.Name, c.argName, c.argType, nil
	}
	if len(byName) > 1 {
		return "", "", introspectionTypeRef{}, fmt.Errorf(
			"introspection found %d Query fields returning %s with arg %q; auto-detect is ambiguous",
			len(byName), entityTypeName, keyField,
		)
	}
	if len(byShape) == 1 {
		c := byShape[0]
		return c.field.Name, c.argName, c.argType, nil
	}
	if len(byShape) == 0 {
		return "", "", introspectionTypeRef{}, fmt.Errorf(
			"introspection found no Query field returning %s with a single argument", entityTypeName,
		)
	}
	return "", "", introspectionTypeRef{}, fmt.Errorf(
		"introspection found %d candidate Query fields for %s; auto-detect is ambiguous",
		len(byShape), entityTypeName,
	)
}

func buildFederationEntitiesQuery(entityTypeName string, fields []string) string {
	var b strings.Builder
	b.WriteString("query($r: [_Any!]!) { _entities(representations: $r) { __typename ... on ")
	b.WriteString(entityTypeName)
	b.WriteString(" { ")
	for i, f := range fields {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(f)
	}
	b.WriteString(" } } }")
	return b.String()
}

func buildGeneratedLookupQuery(fieldName, argName string, argType introspectionTypeRef, entityTypeName string, fields []string) string {
	rendered := renderTypeRef(argType)
	if rendered == "" {
		// Worst-case fallback so we still produce a parseable query — the
		// upstream will reject it loudly which is what we want.
		rendered = "String"
	}
	var b strings.Builder
	b.WriteString("query($k: ")
	b.WriteString(rendered)
	b.WriteString(") { ")
	b.WriteString(fieldName)
	b.WriteString("(")
	b.WriteString(argName)
	b.WriteString(": $k) { __typename ")
	for i, f := range fields {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(f)
	}
	b.WriteString(" } }")
	_ = entityTypeName // kept for readability; the engine doesn't need an inline fragment for plain object queries
	return b.String()
}

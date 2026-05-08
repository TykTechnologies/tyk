package enginev3

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"text/template"

	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/ast"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/astparser"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/plan"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/resolve"
	"github.com/TykTechnologies/tyk/apidef"
)

// entityResolver fetches a fully resolved entity given its key representation.
type entityResolver interface {
	resolve(ctx context.Context, representation map[string]any) (map[string]any, error)
}

// restEntityResolver resolves an entity by issuing an HTTP request to a REST upstream.
// URLTemplate uses Go text/template syntax with `.object` bound to the representation,
// e.g. "/users/{{.object.id}}".
type restEntityResolver struct {
	URLTemplate *template.Template
	Method      string
	Headers     map[string]string
	BodyTpl     *template.Template
	Client      *http.Client
}

func (r *restEntityResolver) resolve(ctx context.Context, representation map[string]any) (map[string]any, error) {
	var urlBuf bytes.Buffer
	if err := r.URLTemplate.Execute(&urlBuf, map[string]any{"object": representation}); err != nil {
		return nil, fmt.Errorf("render entity url: %w", err)
	}

	var body io.Reader
	if r.BodyTpl != nil {
		var bodyBuf bytes.Buffer
		if err := r.BodyTpl.Execute(&bodyBuf, map[string]any{"object": representation}); err != nil {
			return nil, fmt.Errorf("render entity body: %w", err)
		}
		body = &bodyBuf
	}

	method := r.Method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, urlBuf.String(), body)
	if err != nil {
		return nil, fmt.Errorf("build entity request: %w", err)
	}
	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}

	client := r.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("entity upstream call: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read entity response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("entity upstream returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var entity map[string]any
	if err := json.Unmarshal(respBody, &entity); err != nil {
		return nil, fmt.Errorf("parse entity response: %w", err)
	}
	return entity, nil
}

type entitiesDataSourceFactory struct {
	upstreamSchema *ast.Document
	resolvers      map[string]entityResolver
}

func (f *entitiesDataSourceFactory) Planner(ctx context.Context) plan.DataSourcePlanner {
	return &entitiesDataSourcePlanner{
		upstreamSchema: f.upstreamSchema,
		resolvers:      f.resolvers,
	}
}

type entitiesDataSourcePlanner struct {
	upstreamSchema         *ast.Document
	resolvers              map[string]entityResolver
	visitor                *plan.Visitor
	representationsArgName string
}

func (p *entitiesDataSourcePlanner) Register(visitor *plan.Visitor, configuration plan.DataSourceConfiguration, dataSourcePlannerConfiguration plan.DataSourcePlannerConfiguration) error {
	p.visitor = visitor
	p.representationsArgName = "representations"
	p.visitor.Walker.RegisterEnterFieldVisitor(p)
	return nil
}

func (p *entitiesDataSourcePlanner) EnterField(ref int) {
	fieldName := p.visitor.Operation.FieldNameString(ref)
	if fieldName == "_entities" {
		for _, argRef := range p.visitor.Operation.FieldArguments(ref) {
			argName := p.visitor.Operation.ArgumentNameString(argRef)
			if argName == "representations" {
				val := p.visitor.Operation.ArgumentValue(argRef)
				if val.Kind == ast.ValueKindVariable {
					p.representationsArgName = p.visitor.Operation.VariableValueNameString(val.Ref)
				}
			}
		}
	}
}

func (p *entitiesDataSourcePlanner) ConfigureFetch() resolve.FetchConfiguration {
	return resolve.FetchConfiguration{
		Input: `{"representations":$$0$$}`,
		Variables: resolve.Variables{
			&resolve.ContextVariable{
				Path:     []string{p.representationsArgName},
				Renderer: resolve.NewJSONVariableRenderer(),
			},
		},
		DataSource: &entitiesDataSource{resolvers: p.resolvers},
		// The data source emits the standard subgraph response shape
		// (`{"data":{"_entities":[...]}, "errors":[...]}`). We tell the engine to
		// extract `data` only — the engine's plan already has an Array node at
		// path "_entities", so it walks that field itself. Going further (e.g.
		// `["data","_entities"]`) would cause a double navigation and yield the
		// "non-nullable Query._entities._entities" error.
		PostProcessing: resolve.PostProcessingConfiguration{
			SelectResponseDataPath:   []string{"data"},
			SelectResponseErrorsPath: []string{"errors"},
		},
	}
}

// ConfigureSubscription is intentionally empty for the entities data source.
// Apollo Federation does not dispatch subscriptions to `_entities`; subscription
// support lives on the regular GraphQL data source planner. Returning a zero
// SubscriptionConfiguration here is correct and prevents the planner from
// attempting to install subscription wiring for a path that never carries
// subscription operations.
func (p *entitiesDataSourcePlanner) ConfigureSubscription() plan.SubscriptionConfiguration {
	return plan.SubscriptionConfiguration{}
}

func (p *entitiesDataSourcePlanner) DataSourcePlanningBehavior() plan.DataSourcePlanningBehavior {
	return plan.DataSourcePlanningBehavior{
		MergeAliasedRootNodes:      false,
		OverrideFieldPathFromAlias: false,
	}
}

func (p *entitiesDataSourcePlanner) DownstreamResponseFieldAlias(downstreamFieldRef int) (alias string, exists bool) {
	return "", false
}

func (p *entitiesDataSourcePlanner) UpstreamSchema(dataSourceConfig plan.DataSourceConfiguration) *ast.Document {
	return p.upstreamSchema
}

type entitiesDataSource struct {
	resolvers map[string]entityResolver
}

type entitiesInput struct {
	Representations []map[string]any `json:"representations"`
}

// graphqlError mirrors the shape of a GraphQL error object so we can hand the
// engine errors with proper `path` arrays that point at the failing entity.
type graphqlError struct {
	Message string `json:"message"`
	Path    []any  `json:"path,omitempty"`
}

// Load resolves each representation independently. Per the Apollo Federation
// spec, `_entities(representations: [_Any!]!): [_Entity]!` returns a list whose
// elements are nullable — when resolving entity N fails we emit `null` at index
// N in the array and a top-level GraphQL error whose path is
// `["_entities", N]`. The remaining successful entities are still returned.
func (d *entitiesDataSource) Load(ctx context.Context, input []byte, w io.Writer) error {
	var in entitiesInput
	if err := json.Unmarshal(input, &in); err != nil {
		return fmt.Errorf("entitiesDataSource: parse input: %w", err)
	}

	entities := make([]any, len(in.Representations))
	var gqlErrors []graphqlError

	addError := func(idx int, msg string) {
		gqlErrors = append(gqlErrors, graphqlError{
			Message: msg,
			Path:    []any{"_entities", idx},
		})
	}

	for i, rep := range in.Representations {
		typenameRaw, ok := rep["__typename"]
		if !ok {
			entities[i] = nil
			addError(i, "entitiesDataSource: representation missing __typename")
			continue
		}
		typename, ok := typenameRaw.(string)
		if !ok {
			entities[i] = nil
			addError(i, "entitiesDataSource: __typename is not a string")
			continue
		}

		resolver, ok := d.resolvers[typename]
		if !ok {
			// No resolver registered for this type — return the representation
			// as-is so fields included in the representation are still readable.
			entities[i] = rep
			continue
		}

		entity, err := resolver.resolve(ctx, rep)
		if err != nil {
			entities[i] = nil
			addError(i, fmt.Sprintf("entitiesDataSource: resolve %s: %s", typename, err.Error()))
			continue
		}
		if entity == nil {
			// Resolver returned no error but a nil object (e.g. REST upstream
			// answered with a JSON `null`). Treat that as a per-entity
			// resolution failure rather than panicking on `nil` map write.
			entities[i] = nil
			addError(i, fmt.Sprintf("entitiesDataSource: resolve %s: upstream returned null", typename))
			continue
		}
		entity["__typename"] = typename
		entities[i] = entity
	}

	response := map[string]any{
		"data": map[string]any{
			"_entities": entities,
		},
	}
	if len(gqlErrors) > 0 {
		response["errors"] = gqlErrors
	}
	return json.NewEncoder(w).Encode(response)
}

func createEntitiesDataSource(federatedSchema string, resolvers map[string]entityResolver) (plan.DataSourceConfiguration, error) {
	doc, report := astparser.ParseGraphqlDocumentString(federatedSchema)
	if report.HasErrors() {
		return plan.DataSourceConfiguration{}, report
	}

	// Declare every `@key`-decorated type's fields as ChildNodes so the planner
	// knows the entitiesDataSource itself produces the resolved entity payload —
	// otherwise it would try to dispatch a separate fetch to whichever other
	// data source registered RootFields for the entity type.
	childNodes := make([]plan.TypeField, 0)
	for i := range doc.ObjectTypeDefinitions {
		def := doc.ObjectTypeDefinitions[i]
		if !def.HasDirectives {
			continue
		}
		hasKey := false
		for _, dRef := range def.Directives.Refs {
			if doc.DirectiveNameString(dRef) == "key" {
				hasKey = true
				break
			}
		}
		if !hasKey || !def.HasFieldDefinitions {
			continue
		}
		fieldNames := make([]string, 0, len(def.FieldsDefinition.Refs))
		for _, fRef := range def.FieldsDefinition.Refs {
			fieldNames = append(fieldNames, doc.FieldDefinitionNameString(fRef))
		}
		childNodes = append(childNodes, plan.TypeField{
			TypeName:   doc.ObjectTypeDefinitionNameString(i),
			FieldNames: fieldNames,
		})
	}

	return plan.DataSourceConfiguration{
		RootNodes: []plan.TypeField{
			{
				TypeName:   "Query",
				FieldNames: []string{"_entities"},
			},
		},
		ChildNodes: childNodes,
		Factory: &entitiesDataSourceFactory{
			upstreamSchema: &doc,
			resolvers:      resolvers,
		},
		Custom: []byte(`{}`),
	}, nil
}

// buildEntityResolvers walks the API definition's data sources, finds those
// whose RootFields refer to an `@key`-decorated type, and produces a resolver
// for that entity type. The data source's REST/GraphQL upstream is invoked with
// the entity representation as the parent object — `{{.object.<keyField>}}` in
// templates resolves to the representation's value for that key.
func buildEntityResolvers(schemaSDL string, dataSources []apidef.GraphQLEngineDataSource, httpClient *http.Client) (map[string]entityResolver, error) {
	entityTypes, err := keyedEntityTypes(schemaSDL)
	if err != nil {
		return nil, err
	}
	if len(entityTypes) == 0 {
		return nil, nil
	}
	resolvers := map[string]entityResolver{}
	for _, ds := range dataSources {
		for _, rf := range ds.RootFields {
			if !entityTypes[rf.Type] {
				continue
			}
			resolver, err := buildResolverForDataSource(ds, rf.Type, schemaSDL, httpClient)
			if err != nil {
				return nil, fmt.Errorf("build resolver for %s: %w", rf.Type, err)
			}
			if resolver == nil {
				continue
			}
			if _, exists := resolvers[rf.Type]; !exists {
				resolvers[rf.Type] = resolver
			}
		}
	}
	return resolvers, nil
}

// buildResolverForDataSource builds the per-entity resolver for a given data
// source. `entityTypeName` and `customerSchemaSDL` are needed by the GraphQL
// path to discover the upstream lookup field and to know which fields to
// select; the REST path ignores them.
func buildResolverForDataSource(ds apidef.GraphQLEngineDataSource, entityTypeName, customerSchemaSDL string, httpClient *http.Client) (entityResolver, error) {
	switch ds.Kind {
	case apidef.GraphQLEngineDataSourceKindREST:
		var cfg apidef.GraphQLEngineDataSourceConfigREST
		if err := json.Unmarshal(ds.Config, &cfg); err != nil {
			return nil, err
		}
		urlTpl, err := template.New("url").Option("missingkey=error").Parse(cfg.URL)
		if err != nil {
			return nil, fmt.Errorf("parse url template: %w", err)
		}
		var bodyTpl *template.Template
		if cfg.Body != "" {
			bodyTpl, err = template.New("body").Option("missingkey=error").Parse(cfg.Body)
			if err != nil {
				return nil, fmt.Errorf("parse body template: %w", err)
			}
		}
		return &restEntityResolver{
			URLTemplate: urlTpl,
			Method:      cfg.Method,
			Headers:     cfg.Headers,
			BodyTpl:     bodyTpl,
			Client:      httpClient,
		}, nil
	case apidef.GraphQLEngineDataSourceKindGraphQL:
		var cfg apidef.GraphQLEngineDataSourceConfigGraphQL
		if err := json.Unmarshal(ds.Config, &cfg); err != nil {
			return nil, err
		}
		return buildGraphQLEntityResolver(cfg, entityTypeName, customerSchemaSDL, httpClient)
	default:
		// Kafka resolvers not implemented; subscriptions don't fit the
		// _entities request/response shape.
		return nil, nil
	}
}

func keyedEntityTypes(sdl string) (map[string]bool, error) {
	doc, report := astparser.ParseGraphqlDocumentString(sdl)
	if report.HasErrors() {
		return nil, report
	}
	out := map[string]bool{}
	for i := range doc.ObjectTypeDefinitions {
		def := doc.ObjectTypeDefinitions[i]
		if !def.HasDirectives {
			continue
		}
		for _, dRef := range def.Directives.Refs {
			if doc.DirectiveNameString(dRef) == "key" {
				out[doc.ObjectTypeDefinitionNameString(i)] = true
				break
			}
		}
	}
	for i := range doc.ObjectTypeExtensions {
		ext := doc.ObjectTypeExtensions[i]
		if !ext.HasDirectives {
			continue
		}
		for _, dRef := range ext.Directives.Refs {
			if doc.DirectiveNameString(dRef) == "key" {
				out[doc.ObjectTypeExtensionNameString(i)] = true
				break
			}
		}
	}
	return out, nil
}

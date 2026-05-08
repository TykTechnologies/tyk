package enginev3

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/ast"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/astparser"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/astprinter"
	graphqldatasource "github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/datasource/graphql_datasource"
	kafkadatasource "github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/datasource/kafka_datasource"
	restdatasource "github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/datasource/rest_datasource"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/datasource/staticdatasource"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/plan"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/federation"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/graphql"
	"github.com/TykTechnologies/tyk/apidef"
)

// federationLinkURLPrefix matches any Apollo Federation `@link` URL — both
// v1.x and v2.x point at the same `apollo.dev/federation/` namespace.
// Detecting the prefix lets us tell "customer already declared a federation
// version" apart from "customer just wrote @key types".
const federationLinkURLPrefix = "https://specs.apollo.dev/federation/"

// federationV2LinkDirective is prepended to the SDL emitted by `_service { sdl }`
// when the customer's schema is federation-shaped (has `@key`) but does not
// itself declare a federation version. Without this directive, Apollo Rover
// and Apollo Router classify Tyk as a federation v1 subgraph and the default
// v2 composition pipeline rejects it.
const federationV2LinkDirective = `extend schema @link(url: "https://specs.apollo.dev/federation/v2.5", import: ["@key", "@external", "@requires", "@provides", "@extends", "@interfaceObject", "@shareable"])`

// serviceSDL returns the SDL string that should be served by the federation
// `_service { sdl }` field. If the customer SDL already declares a federation
// version via `@link(url: "https://specs.apollo.dev/federation/...")` (v1 or
// v2) we emit it verbatim (modulo orphan-Query-field stripping). If it has no
// such `@link` but contains any `@key` directive — i.e. it's federation-shaped
// but version-less — we auto-prepend a v2 `@link` so Apollo tooling treats Tyk
// as a federation v2 subgraph. Plain GraphQL APIs (no `@key`, no `@link`) are
// passed through unchanged.
//
// For federation-shaped SDLs (anything carrying `@key` or an explicit
// federation `@link`), we additionally strip any `Query` field whose name is
// not registered as a `RootField` of an active data source. Such "orphan"
// Query fields would otherwise be advertised in the supergraph composition,
// and Apollo Router would route queries against them to Tyk — but the UDG
// planner has no data source for them, so it returns
// `Failed to fetch from Subgraph at path 'query.<field>'`. Stripping them
// from the SDL keeps Tyk's advertised subgraph schema honest while leaving
// the customer's actual schema (used for validation/planning) untouched.
func serviceSDL(customerSDL string, dataSources []apidef.GraphQLEngineDataSource) string {
	hasLink := schemaHasFederationLink(customerSDL)

	keyed, err := keyedEntityTypes(customerSDL)
	federationShaped := hasLink || (err == nil && len(keyed) > 0)

	if !federationShaped {
		// Plain GraphQL APIs are not subgraphs — leave them alone.
		return customerSDL
	}

	stripped, ok := stripOrphanQueryFields(customerSDL, dataSources)
	if !ok {
		// Best-effort: if we can't parse/print, fall back to the raw SDL so
		// `_service { sdl }` still returns something usable.
		stripped = customerSDL
	}

	if hasLink {
		return stripped
	}
	return federationV2LinkDirective + "\n" + stripped
}

// stripOrphanQueryFields removes any Query field from the SDL whose name is
// not registered under a data source's RootFields with `Type == "Query"`.
// Returns (modified-sdl, true) on success, ("", false) on parse/print error.
//
// When stripping leaves the Query type with no surviving fields, the entire
// Query type definition (or extension) is dropped from the SDL. An empty
// `type Query {}` block isn't valid GraphQL syntax, and Apollo Federation v2
// composition is happy to receive a subgraph SDL with no Query type at all —
// it injects `_entities` and `_service` itself during composition. This is
// the typical shape of an "entity-only" subgraph.
func stripOrphanQueryFields(sdl string, dataSources []apidef.GraphQLEngineDataSource) (string, bool) {
	registered := registeredQueryFieldNames(dataSources)

	doc, report := astparser.ParseGraphqlDocumentString(sdl)
	if report.HasErrors() {
		return "", false
	}

	type rootNodeRemoval struct {
		kind ast.NodeKind
		ref  int
	}
	var toRemove []rootNodeRemoval

	for i := range doc.ObjectTypeDefinitions {
		if doc.ObjectTypeDefinitionNameString(i) != "Query" {
			continue
		}
		def := &doc.ObjectTypeDefinitions[i]
		def.FieldsDefinition.Refs = filterFieldRefsByRegistered(&doc, def.FieldsDefinition.Refs, registered)
		def.HasFieldDefinitions = len(def.FieldsDefinition.Refs) > 0
		if !def.HasFieldDefinitions {
			toRemove = append(toRemove, rootNodeRemoval{kind: ast.NodeKindObjectTypeDefinition, ref: i})
		}
	}
	for i := range doc.ObjectTypeExtensions {
		if doc.ObjectTypeExtensionNameString(i) != "Query" {
			continue
		}
		ext := &doc.ObjectTypeExtensions[i]
		ext.FieldsDefinition.Refs = filterFieldRefsByRegistered(&doc, ext.FieldsDefinition.Refs, registered)
		ext.HasFieldDefinitions = len(ext.FieldsDefinition.Refs) > 0
		if !ext.HasFieldDefinitions {
			toRemove = append(toRemove, rootNodeRemoval{kind: ast.NodeKindObjectTypeExtension, ref: i})
		}
	}

	// Drop any empty Query type/extension from RootNodes so the printer
	// doesn't emit `type Query` with no body.
	if len(toRemove) > 0 {
		filtered := doc.RootNodes[:0]
		for _, rn := range doc.RootNodes {
			drop := false
			for _, r := range toRemove {
				if rn.Kind == r.kind && rn.Ref == r.ref {
					drop = true
					break
				}
			}
			if !drop {
				filtered = append(filtered, rn)
			}
		}
		doc.RootNodes = filtered
	}

	out, err := astprinter.PrintStringIndent(&doc, nil, "  ")
	if err != nil {
		return "", false
	}
	return out, true
}

// registeredQueryFieldNames collects field names from each data source's
// RootFields entry whose Type is "Query". These are the only Query-level
// fields the UDG planner can resolve.
func registeredQueryFieldNames(dataSources []apidef.GraphQLEngineDataSource) map[string]bool {
	out := map[string]bool{}
	for _, ds := range dataSources {
		for _, rf := range ds.RootFields {
			if rf.Type != "Query" {
				continue
			}
			for _, f := range rf.Fields {
				out[f] = true
			}
		}
	}
	return out
}

// filterFieldRefsByRegistered returns the subset of fieldRefs whose field name
// is present in the `registered` set.
func filterFieldRefsByRegistered(doc *ast.Document, fieldRefs []int, registered map[string]bool) []int {
	kept := make([]int, 0, len(fieldRefs))
	for _, ref := range fieldRefs {
		if registered[doc.FieldDefinitionNameString(ref)] {
			kept = append(kept, ref)
		}
	}
	return kept
}

// schemaHasFederationLink reports whether the SDL declares an Apollo
// Federation version through an `@link` directive on `schema` /
// `extend schema`. A failure to parse is treated as "no link", so the caller
// falls back to the auto-prepend path or pass-through.
func schemaHasFederationLink(sdl string) bool {
	doc, report := astparser.ParseGraphqlDocumentString(sdl)
	if report.HasErrors() {
		return false
	}
	for i := range doc.SchemaDefinitions {
		def := doc.SchemaDefinitions[i]
		if def.HasDirectives && directivesContainFederationLink(&doc, def.Directives.Refs) {
			return true
		}
	}
	for i := range doc.SchemaExtensions {
		ext := doc.SchemaExtensions[i]
		if ext.HasDirectives && directivesContainFederationLink(&doc, ext.Directives.Refs) {
			return true
		}
	}
	return false
}

// directivesContainFederationLink looks through the given directive refs for
// `@link(url: "https://specs.apollo.dev/federation/...")`.
func directivesContainFederationLink(doc *ast.Document, directiveRefs []int) bool {
	for _, dRef := range directiveRefs {
		if doc.DirectiveNameString(dRef) != "link" {
			continue
		}
		val, ok := doc.DirectiveArgumentValueByName(dRef, []byte("url"))
		if !ok || val.Kind != ast.ValueKindString {
			continue
		}
		if strings.HasPrefix(doc.StringValueContentString(val.Ref), federationLinkURLPrefix) {
			return true
		}
	}
	return false
}

type UniversalDataGraph struct {
	ApiDefinition   *apidef.APIDefinition
	HttpClient      *http.Client
	StreamingClient *http.Client
	Schema          *graphql.Schema

	subscriptionClientFactory graphqldatasource.GraphQLSubscriptionClientFactory
}

func (u *UniversalDataGraph) EngineConfigV3() (*graphql.EngineV2Configuration, error) {
	var err error
	if u.Schema == nil {
		schemaStr := u.ApiDefinition.GraphQL.Schema
		// Inject Apollo Federation Schema
		schemaStr, err = federation.BuildFederationSchema(schemaStr, schemaStr)
		if err != nil {
			return nil, err
		}
		u.Schema, err = parseSchema(schemaStr)
		if err != nil {
			return nil, err
		}
	}

	conf := graphql.NewEngineV2Configuration(u.Schema)
	conf.EnableSingleFlight(false)

	fieldConfigs := u.engineConfigV2FieldConfigs()
	datsSources, err := u.engineConfigV2DataSources()
	if err != nil {
		return nil, err
	}

	// Add entities datasource. The resolvers map links each `@key`-decorated entity
	// type to its upstream (REST today; GraphQL/Kafka not yet supported).
	federatedSchemaSDL := string(u.Schema.Document())
	entityResolvers, err := buildEntityResolvers(u.ApiDefinition.GraphQL.Schema, u.ApiDefinition.GraphQL.Engine.DataSources, u.HttpClient)
	if err != nil {
		return nil, err
	}
	entitiesDS, err := createEntitiesDataSource(federatedSchemaSDL, entityResolvers)
	if err != nil {
		return nil, err
	}
	datsSources = append(datsSources, entitiesDS)

	// Add service datasource. ChildNodes for `_Service.sdl` are populated below by
	// determineChildNodes against the federation-augmented schema, so the planner
	// knows this data source can resolve `sdl` selections under `_service`.
	serviceDataSource := plan.DataSourceConfiguration{
		RootNodes: []plan.TypeField{
			{
				TypeName:   "Query",
				FieldNames: []string{"_service"},
			},
		},
		Factory: &staticdatasource.Factory{},
		Custom: staticdatasource.ConfigJSON(staticdatasource.Configuration{
			// Emit the federation-aware SDL: serviceSDL preserves an explicit
			// `@link` if the customer wrote one, auto-prepends a v2 `@link`
			// when the SDL has `@key` but no version declaration, or returns
			// the SDL untouched when there's nothing federation-shaped. For
			// federation subgraphs it also strips any Query field that isn't
			// backed by a data source — those would otherwise be routed to
			// Tyk by Apollo Router and fail with "Failed to fetch from
			// Subgraph at path 'query.<field>'".
			Data: `{"_service":{"sdl":` + strconv.Quote(serviceSDL(u.ApiDefinition.GraphQL.Schema, u.ApiDefinition.GraphQL.Engine.DataSources)) + `}}`,
		}),
	}
	datsSources = append(datsSources, serviceDataSource)

	// Auto-populate ChildNodes for the entities and service data sources by
	// walking the federation-augmented schema. We pass a slice containing only
	// the federation-internal data sources because determineChildNodes appends
	// to ChildNodes — the user data sources were already processed inside
	// engineConfigV2DataSources and re-running them here would duplicate entries.
	federationDataSources := datsSources[len(datsSources)-2:]
	if err := u.determineChildNodes(federationDataSources); err != nil {
		return nil, err
	}

	conf.SetFieldConfigurations(fieldConfigs)
	conf.SetDataSources(datsSources)

	return &conf, nil
}

func (u *UniversalDataGraph) engineConfigV2FieldConfigs() (planFieldConfigs plan.FieldConfigurations) {
	for _, fc := range u.ApiDefinition.GraphQL.Engine.FieldConfigs {
		planFieldConfig := plan.FieldConfiguration{
			TypeName:              fc.TypeName,
			FieldName:             fc.FieldName,
			DisableDefaultMapping: fc.DisableDefaultMapping,
			Path:                  fc.Path,
		}

		planFieldConfigs = append(planFieldConfigs, planFieldConfig)
	}

	generatedArgs := u.Schema.GetAllFieldArguments(graphql.NewSkipReservedNamesFunc())
	generatedArgsAsLookupMap := graphql.CreateTypeFieldArgumentsLookupMap(generatedArgs)
	u.engineConfigV2Arguments(&planFieldConfigs, generatedArgsAsLookupMap)

	return planFieldConfigs
}

func (u *UniversalDataGraph) engineConfigV2DataSources() (planDataSources []plan.DataSourceConfiguration, err error) {
	for _, ds := range u.ApiDefinition.GraphQL.Engine.DataSources {
		planDataSource := plan.DataSourceConfiguration{
			RootNodes: []plan.TypeField{},
		}

		for _, typeField := range ds.RootFields {
			planTypeField := plan.TypeField{
				TypeName:   typeField.Type,
				FieldNames: typeField.Fields,
			}

			planDataSource.RootNodes = append(planDataSource.RootNodes, planTypeField)
		}

		switch ds.Kind {
		case apidef.GraphQLEngineDataSourceKindREST:
			var restConfig apidef.GraphQLEngineDataSourceConfigREST
			err = json.Unmarshal(ds.Config, &restConfig)
			if err != nil {
				return nil, err
			}

			planDataSource.Factory = &restdatasource.Factory{
				Client: u.HttpClient,
			}

			urlWithoutQueryParams, queryConfigs, err := extractURLQueryParamsForEngineV2(restConfig.URL, restConfig.Query)
			if err != nil {
				return nil, err
			}

			planDataSource.Custom = restdatasource.ConfigJSON(restdatasource.Configuration{
				Fetch: restdatasource.FetchConfiguration{
					URL:    urlWithoutQueryParams,
					Method: restConfig.Method,
					Body:   restConfig.Body,
					Query:  queryConfigs,
					Header: ConvertApiDefinitionHeadersToHttpHeaders(restConfig.Headers),
				},
			})

		case apidef.GraphQLEngineDataSourceKindGraphQL:
			var graphqlConfig apidef.GraphQLEngineDataSourceConfigGraphQL
			err = json.Unmarshal(ds.Config, &graphqlConfig)
			if err != nil {
				return nil, err
			}

			if graphqlConfig.HasOperation {
				planDataSource.Factory = &restdatasource.Factory{
					Client: u.HttpClient,
				}
				planDataSource.Custom, err = generateRestDataSourceFromGraphql(graphqlConfig)
				if err != nil {
					return nil, err
				}
				break
			}

			planDataSource.Factory, err = createGraphQLDataSourceFactory(createGraphQLDataSourceFactoryParams{
				graphqlConfig:             graphqlConfig,
				subscriptionClientFactory: subscriptionClientFactoryOrDefault(u.subscriptionClientFactory),
				httpClient:                u.HttpClient,
				streamingClient:           u.StreamingClient,
			})
			if err != nil {
				return nil, err
			}

			planDataSource.Custom = graphqldatasource.ConfigJson(graphqlDataSourceConfiguration(
				graphqlConfig.URL,
				graphqlConfig.Method,
				graphqlConfig.Headers,
				graphqlConfig.SubscriptionType,
			))

		case apidef.GraphQLEngineDataSourceKindKafka:
			var kafkaConfig apidef.GraphQLEngineDataSourceConfigKafka
			err = json.Unmarshal(ds.Config, &kafkaConfig)
			if err != nil {
				return nil, err
			}

			planDataSource.Factory = &kafkadatasource.Factory{}
			planDataSource.Custom = kafkadatasource.ConfigJSON(kafkadatasource.Configuration{
				Subscription: kafkadatasource.SubscriptionConfiguration{
					BrokerAddresses:      kafkaConfig.BrokerAddresses,
					Topics:               kafkaConfig.Topics,
					GroupID:              kafkaConfig.GroupID,
					ClientID:             kafkaConfig.ClientID,
					KafkaVersion:         kafkaConfig.KafkaVersion,
					StartConsumingLatest: kafkaConfig.StartConsumingLatest,
					BalanceStrategy:      kafkaConfig.BalanceStrategy,
					IsolationLevel:       kafkaConfig.IsolationLevel,
					SASL: kafkadatasource.SASL{
						Enable:   kafkaConfig.SASL.Enable,
						User:     kafkaConfig.SASL.User,
						Password: kafkaConfig.SASL.Password,
					},
				},
			})
		}

		planDataSources = append(planDataSources, planDataSource)
	}

	err = u.determineChildNodes(planDataSources)
	return planDataSources, err
}

func (u *UniversalDataGraph) engineConfigV2Arguments(fieldConfs *plan.FieldConfigurations, generatedArgs map[graphql.TypeFieldLookupKey]graphql.TypeFieldArguments) {
	for i := range *fieldConfs {
		if len(generatedArgs) == 0 {
			return
		}

		lookupKey := graphql.CreateTypeFieldLookupKey((*fieldConfs)[i].TypeName, (*fieldConfs)[i].FieldName)
		currentArgs, ok := generatedArgs[lookupKey]
		if !ok {
			continue
		}

		(*fieldConfs)[i].Arguments = createArgumentConfigurationsForArgumentNames(currentArgs.ArgumentNames...)
		delete(generatedArgs, lookupKey)
	}

	for _, genArgs := range generatedArgs {
		*fieldConfs = append(*fieldConfs, plan.FieldConfiguration{
			TypeName:  genArgs.TypeName,
			FieldName: genArgs.FieldName,
			Arguments: createArgumentConfigurationsForArgumentNames(genArgs.ArgumentNames...),
		})
	}
}

func (u *UniversalDataGraph) determineChildNodes(planDataSources []plan.DataSourceConfiguration) error {
	for i := range planDataSources {
		for j := range planDataSources[i].RootNodes {
			typeName := planDataSources[i].RootNodes[j].TypeName
			for k := range planDataSources[i].RootNodes[j].FieldNames {
				fieldName := planDataSources[i].RootNodes[j].FieldNames[k]
				typeFields := u.Schema.GetAllNestedFieldChildrenFromTypeField(typeName, fieldName, graphql.NewIsDataSourceConfigV2RootFieldSkipFunc(planDataSources))

				children := make([]plan.TypeField, 0)
				for _, tf := range typeFields {
					childNode := plan.TypeField{
						TypeName:   tf.TypeName,
						FieldNames: tf.FieldNames,
					}
					children = append(children, childNode)
				}
				planDataSources[i].ChildNodes = append(planDataSources[i].ChildNodes, children...)
			}
		}
	}
	return nil
}

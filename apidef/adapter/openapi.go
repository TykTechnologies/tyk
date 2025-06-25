package adapter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"

	"github.com/TykTechnologies/graphql-go-tools/pkg/astprinter"
	"github.com/TykTechnologies/graphql-go-tools/pkg/operationreport"
	"github.com/TykTechnologies/graphql-translator/openapi"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/getkin/kin-openapi/openapi3"
)

const defaultRequestBodyMimeType = "application/json"

const (
	GraphQLTypeQuery    = "Query"
	GraphQLTypeMutation = "Mutation"
)

type openAPI struct {
	orgId         string
	input         []byte
	report        *operationreport.Report
	apiDefinition *apidef.APIDefinition
	document      *openapi3.T
}

func extractRequestBody(mime string, operation *openapi3.Operation) (*openapi3.SchemaRef, error) {
	mediaType := operation.RequestBody.Value.Content.Get(mime)
	if mediaType == nil {
		return nil, fmt.Errorf("no media found for mime type %s", mime)
	}

	if mediaType.Schema != nil {
		return mediaType.Schema, nil
	}
	return nil, fmt.Errorf("no schema found for mime type %s", mime)
}

func (o *openAPI) prepareGraphQLEngineConfig() error {
	if o.document == nil {
		return fmt.Errorf("document is nil")
	}

	if len(o.document.Servers) == 0 {
		return errors.New("no server defined in OpenAPI spec")
	}

	graphqlTypes := map[string][]string{
		GraphQLTypeQuery:    {http.MethodGet},
		GraphQLTypeMutation: {http.MethodPost, http.MethodPut, http.MethodDelete},
	}

	// We only support one server definition and always pick the first one.
	server, err := url.Parse(o.document.Servers[0].URL)
	if err != nil {
		return err
	}

	for rawEndpoint, pathItem := range o.document.Paths.Map() {
		// Converts /pets/{id} to /pets/{{.arguments.id}}
		endpoint := processArgumentSection(rawEndpoint)

		for graphqlType, methods := range graphqlTypes {
			for _, method := range methods {
				operation := pathItem.GetOperation(method)
				if operation == nil {
					continue
				}

				parsedEndpoint, err := url.Parse(endpoint)
				if err != nil {
					return fmt.Errorf("failed to parse endpoint: %w", err)
				}
				parsedEndpoint.Scheme = server.Scheme
				parsedEndpoint.Host = server.Host
				parsedEndpoint.Path = path.Join(server.Path, parsedEndpoint.Path)

				query := parsedEndpoint.Query()
				for _, parameter := range operation.Parameters {
					if parameter.Value.In == "query" {
						query.Add(parameter.Value.Name, fmt.Sprintf("{{.arguments.%s}}", parameter.Value.Name))
					}
				}
				unescapedQuery, err := url.PathUnescape(query.Encode())
				if err != nil {
					return err
				}
				parsedEndpoint.RawQuery = unescapedQuery

				fieldName := openapi.MakeFieldNameFromOperationID(operation.OperationID)
				if fieldName == "" {
					// If "operationId" is not defined by the user, try to make an operationId
					// from endpoint's itself. The same technique is used by IBM/openapi-to-graphql tool.
					if graphqlType == GraphQLTypeQuery {
						fieldName = openapi.MakeFieldNameFromEndpoint(rawEndpoint)
					} else if graphqlType == GraphQLTypeMutation {
						// IBM/openapi-to-graphql adds method name to the generated field name.
						fieldName = openapi.MakeFieldNameFromEndpointForMutation(method, rawEndpoint)
					}
				}

				fieldConfig := apidef.GraphQLFieldConfig{
					TypeName:              graphqlType,
					FieldName:             fieldName,
					DisableDefaultMapping: true, // See TT-TT-8728
					Path:                  []string{fieldName},
				}
				o.apiDefinition.GraphQL.Engine.FieldConfigs = append(o.apiDefinition.GraphQL.Engine.FieldConfigs, fieldConfig)

				rootFields := []apidef.GraphQLTypeFields{
					{
						Type: graphqlType,
						Fields: []string{
							fieldName,
						},
					},
				}
				dataSourceConfig := apidef.GraphQLEngineDataSource{
					Kind:       apidef.GraphQLEngineDataSourceKindREST,
					Name:       fieldName,
					RootFields: rootFields,
				}

				dataSourceURL, err := url.PathUnescape(parsedEndpoint.String())
				if err != nil {
					return err
				}

				restConfig := apidef.GraphQLEngineDataSourceConfigREST{
					URL:     dataSourceURL,
					Method:  method,
					Headers: make(map[string]string),
					Query:   []apidef.QueryVariable{},
				}
				if operation.RequestBody != nil {
					inputTypeSchema, err := extractRequestBody(defaultRequestBodyMimeType, operation)
					if err != nil {
						return err
					}
					inputTypeName := openapi.MakeInputTypeName(inputTypeSchema.Ref)
					restConfig.Body = fmt.Sprintf("{{ .arguments.%s }}", openapi.MakeParameterName(inputTypeName))
				}

				encodedRestConfig, err := json.Marshal(restConfig)
				if err != nil {
					return err
				}

				dataSourceConfig.Config = encodedRestConfig
				o.apiDefinition.GraphQL.Engine.DataSources = append(o.apiDefinition.GraphQL.Engine.DataSources, dataSourceConfig)
			}
		}
	}

	return nil
}

func (o *openAPI) Import() (*apidef.APIDefinition, error) {
	document, err := openapi.ParseOpenAPIDocument(o.input)
	if err != nil {
		return nil, err
	}

	o.document = document
	o.apiDefinition = newApiDefinition(o.document.Info.Title, o.orgId)

	if err := o.prepareGraphQLEngineConfig(); err != nil {
		return nil, err
	}

	// We iterate over the maps to create a new API definition. This leads to the random placement of
	// items in various arrays in the resulting JSON document. In order to test the OpenAPI converter
	// with fixtures and prevent randomness, we sort various data structures here.
	sortFieldConfigsByName(o.apiDefinition)
	sortDataSourcesByName(o.apiDefinition)

	graphqlDocument := openapi.ImportParsedOpenAPIv3Document(o.document, o.report)
	if o.report.HasErrors() {
		return nil, o.report
	}

	w := &bytes.Buffer{}
	err = astprinter.PrintIndent(graphqlDocument, nil, []byte("  "), w)
	if err != nil {
		return nil, err
	}
	o.apiDefinition.GraphQL.Schema = w.String()

	return o.apiDefinition, nil
}

func NewOpenAPIAdapter(orgId string, input []byte) ImportAdapter {
	report := operationreport.Report{}
	return &openAPI{
		report: &report,
		input:  input,
		orgId:  orgId,
	}
}

var _ ImportAdapter = (*openAPI)(nil)

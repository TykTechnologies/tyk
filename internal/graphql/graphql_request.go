package graphql

import (
	"strings"

	"github.com/buger/jsonparser"

	"github.com/TykTechnologies/graphql-go-tools/pkg/ast"
	"github.com/TykTechnologies/graphql-go-tools/pkg/astparser"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/TykTechnologies/tyk-pump/analytics"
)

type GraphRequest struct {
	graphql.Request

	operationRef      int
	requestDoc        *ast.Document
	schema            *ast.Document
	OriginalVariables []byte
}

func NewRequestFromBodySchema(rawRequest, schema string) (*GraphRequest, error) {
	var gqlRequest graphql.Request
	if err := graphql.UnmarshalRequest(strings.NewReader(rawRequest), &gqlRequest); err != nil {
		return nil, err
	}
	originalVariables := gqlRequest.Variables

	requestDoc, opReport := astparser.ParseGraphqlDocumentString(gqlRequest.Query)
	if opReport.HasErrors() {
		return nil, opReport
	}

	sh, err := graphql.NewSchemaFromString(schema)
	if err != nil {
		return nil, err
	}

	schemaDoc, opReport := astparser.ParseGraphqlDocumentBytes(sh.Document())
	if opReport.HasErrors() {
		return nil, opReport
	}

	res, err := gqlRequest.Normalize(sh)
	if err != nil {
		return nil, err
	}
	if !res.Successful {
		return nil, res.Errors
	}

	return &GraphRequest{
		Request:           gqlRequest,
		operationRef:      ast.InvalidRef,
		requestDoc:        &requestDoc,
		schema:            &schemaDoc,
		OriginalVariables: originalVariables,
	}, nil
}

func (g *GraphRequest) GraphErrors(response []byte) ([]string, error) {
	errors := make([]string, 0)
	errBytes, t, _, err := jsonparser.Get(response, "errors")
	// check if the errors key exists in the response
	if err != nil {
		if err == jsonparser.KeyPathNotFoundError {
			return nil, nil
		}
		return nil, err
	}
	if t != jsonparser.NotExist {
		if _, err := jsonparser.ArrayEach(errBytes, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
			message, err := jsonparser.GetString(value, "message")
			if err != nil {
				return
			}
			errors = append(errors, message)
		}); err != nil {
			return nil, err
		}
	}
	return errors, nil
}

func (g *GraphRequest) RootFields() []string {
	operationRef := g.findOperationRef()
	rootFields := make([]string, 0)
	if !g.requestDoc.OperationDefinitions[operationRef].HasSelections {
		return rootFields
	}

	for _, selectionRef := range g.requestDoc.SelectionSets[g.requestDoc.OperationDefinitions[operationRef].SelectionSet].SelectionRefs {
		if selectionRef == ast.InvalidRef || g.requestDoc.Selections[selectionRef].Kind != ast.SelectionKindField {
			continue
		}
		rootFields = append(rootFields, g.requestDoc.FieldNameString(g.requestDoc.Selections[selectionRef].Ref))
	}
	return rootFields
}

func (g *GraphRequest) TypesAndFields() map[string][]string {
	rootOperationTypeName := g.schemaRootOperationTypeName()
	typesAndFields := make(map[string][]string)
	operationDefRef := g.findOperationRef()
	if !g.requestDoc.OperationDefinitions[operationDefRef].HasSelections {
		return nil
	}
	g.recursivelyExtractTypeAndFieldsDefinition(rootOperationTypeName, g.requestDoc.OperationDefinitions[operationDefRef].SelectionSet, typesAndFields, false)
	return typesAndFields
}

// recursivelyExtractTypeAndFieldsDefinition extracts the Type name and field name from the selectionSet passed
// and adds it to the typesAndFields map
func (g *GraphRequest) recursivelyExtractTypeAndFieldsDefinition(name string, selectionSetRef int, typesFields map[string][]string, shouldRecord bool) {
	fields := make([]string, 0)
	node, found := g.schema.Index.FirstNodeByNameStr(name)
	if !found {
		return
	}
	if node.Kind != ast.NodeKindObjectTypeDefinition || node.Ref == ast.InvalidRef {
		return
	}
	objTypeDefRef := node.Ref
	if !g.schema.ObjectTypeDefinitions[objTypeDefRef].HasFieldDefinitions {
		return
	}

	// loop through selection set fields ad match to fields in field definition
	for _, selection := range g.requestDoc.SelectionSets[selectionSetRef].SelectionRefs {
		if g.requestDoc.Selections[selection].Kind != ast.SelectionKindField {
			continue
		}
		fieldRef := g.requestDoc.Selections[selection].Ref
		fieldName := g.requestDoc.FieldNameString(fieldRef)
		// check the objecttypedef for the field and check if it exists
		if !g.schema.ObjectTypeDefinitionHasField(objTypeDefRef, []byte(fieldName)) {
			continue
		}

		for _, fieldDefinitionRef := range g.schema.ObjectTypeDefinitions[objTypeDefRef].FieldsDefinition.Refs {
			if g.schema.FieldDefinitionNameString(fieldDefinitionRef) != fieldName {
				continue
			}
			fields = append(fields, fieldName)
			// check type and recursively call function
			typeRef := g.schema.FieldDefinitions[fieldDefinitionRef].Type
			underlyingType := g.schema.ResolveUnderlyingType(typeRef)
			if !g.schema.TypeIsScalar(underlyingType, g.schema) && g.requestDoc.Fields[fieldRef].HasSelections {
				typeName := g.schema.ResolveTypeNameString(typeRef)
				g.recursivelyExtractTypeAndFieldsDefinition(typeName, g.requestDoc.Fields[fieldRef].SelectionSet, typesFields, true)
			}
		}
	}

	if shouldRecord {
		typesFields[name] = append(typesFields[name], fields...)
	}
	return
}

func (g *GraphRequest) schemaRootOperationTypeName() string {
	operationType, _ := g.Request.OperationType()
	switch operationType {
	case graphql.OperationTypeQuery:
		return g.schema.Index.QueryTypeName.String()
	case graphql.OperationTypeMutation:
		return g.schema.Index.MutationTypeName.String()
	case graphql.OperationTypeSubscription:
		return g.schema.Index.SubscriptionTypeName.String()
	default:
		return ""
	}
}

func (g *GraphRequest) OperationType() analytics.GraphQLOperations {
	t, _ := g.Request.OperationType()
	switch t {
	case graphql.OperationTypeQuery:
		return analytics.OperationQuery
	case graphql.OperationTypeMutation:
		return analytics.OperationMutation
	case graphql.OperationTypeSubscription:
		return analytics.OperationSubscription
	default:
		return analytics.OperationUnknown
	}
}

func (g *GraphRequest) findOperationRef() int {
	if g.operationRef != ast.InvalidRef {
		return g.operationRef
	}
	for _, rootNode := range g.requestDoc.RootNodes {
		if rootNode.Kind != ast.NodeKindOperationDefinition {
			continue
		}

		if g.Request.OperationName != "" && g.requestDoc.OperationDefinitionNameString(rootNode.Ref) != g.Request.OperationName {
			continue
		}

		return rootNode.Ref
	}
	return ast.InvalidRef
}

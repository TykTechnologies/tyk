package graphql

import (
	"bytes"
	"github.com/TykTechnologies/graphql-go-tools/pkg/astnormalization"
	"github.com/TykTechnologies/graphql-go-tools/pkg/astvisitor"
	"github.com/TykTechnologies/graphql-go-tools/pkg/operationreport"
	"strings"

	"github.com/buger/jsonparser"

	"github.com/TykTechnologies/graphql-go-tools/pkg/ast"
	"github.com/TykTechnologies/graphql-go-tools/pkg/astparser"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/TykTechnologies/tyk-pump/analytics"
)

type GraphStatsExtractionVisitor struct {
	OriginalVariables []byte

	walker *astvisitor.Walker

	gqlRequest *graphql.Request
	operation  *ast.Document
	schema     *ast.Document

	skipOperation bool
	operationRef  int

	typesFields map[string][]string
	rootFields  map[string]struct{}
}

func (g *GraphStatsExtractionVisitor) EnterOperationDefinition(ref int) {
	if g.gqlRequest.OperationName == "" && ref == 0 {
		g.skipOperation = false
		g.operationRef = ref
		return
	} else if g.gqlRequest.OperationName == "" && ref != 0 {
		g.skipOperation = true
		return
	}

	opName := g.operation.OperationDefinitionNameBytes(ref)
	if bytes.Equal(opName, []byte(g.gqlRequest.OperationName)) {
		g.skipOperation = false
		g.operationRef = ref
	} else {
		g.skipOperation = true
	}
}

func NewGraphStatsExtractor() *GraphStatsExtractionVisitor {
	walker := astvisitor.NewWalker(48)
	extractor := &GraphStatsExtractionVisitor{
		walker:       &walker,
		typesFields:  make(map[string][]string),
		rootFields:   make(map[string]struct{}),
		operationRef: ast.InvalidRef,
	}
	walker.RegisterEnterOperationVisitor(extractor)
	walker.RegisterEnterFieldVisitor(extractor)
	return extractor
}

func (g *GraphStatsExtractionVisitor) GraphErrors(response []byte) ([]string, error) {
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

func (g *GraphStatsExtractionVisitor) ExtractStats(rawRequest, response, schema string) (analytics.GraphQLStats, error) {
	var stats analytics.GraphQLStats
	var gqlRequest graphql.Request
	if err := graphql.UnmarshalRequest(strings.NewReader(rawRequest), &gqlRequest); err != nil {
		return stats, err
	}
	g.gqlRequest = &gqlRequest

	// generate request and schema doc
	requestDoc, opReport := astparser.ParseGraphqlDocumentString(g.gqlRequest.Query)
	if opReport.HasErrors() {
		return stats, opReport
	}
	g.operation = &requestDoc

	sh, err := graphql.NewSchemaFromString(schema)
	if err != nil {
		return stats, err
	}
	schemaDoc, opReport := astparser.ParseGraphqlDocumentBytes(sh.Document())
	if opReport.HasErrors() {
		return stats, opReport
	}
	g.schema = &schemaDoc

	// normalize and extract fragments
	var report operationreport.Report
	normalizer := astnormalization.NewNormalizer(true, false)
	if g.gqlRequest.OperationName != "" {
		normalizer.NormalizeNamedOperation(g.operation, g.schema, []byte(g.gqlRequest.OperationName), &report)
	} else {
		normalizer.NormalizeOperation(g.operation, g.schema, &report)
	}
	if report.HasErrors() {
		return stats, report
	}

	g.walker.Walk(g.operation, g.schema, &report)
	if report.HasErrors() {
		return stats, report
	}

	stats.IsGraphQL = true
	stats.Types = g.typesFields
	for key := range g.rootFields {
		stats.RootFields = append(stats.RootFields, key)
	}
	stats.OperationType = g.AnalyticsOperationTypes()
	graphErrors, err := g.GraphErrors([]byte(response))
	for _, e := range graphErrors {
		stats.Errors = append(stats.Errors, analytics.GraphError{
			Message: e,
		})
	}
	stats.HasErrors = len(stats.Errors) > 0
	return stats, nil
}

func (g *GraphStatsExtractionVisitor) AnalyticsOperationTypes() analytics.GraphQLOperations {
	if g.gqlRequest == nil {
		return analytics.OperationUnknown
	}
	op, _ := g.gqlRequest.OperationType()
	switch op {
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

func (g *GraphStatsExtractionVisitor) EnterField(ref int) {
	if g.skipOperation {
		return
	}
	fieldName := g.operation.FieldNameString(ref)
	parent := g.schema.NodeNameBytes(g.walker.EnclosingTypeDefinition)
	if bytes.Equal(parent, g.schema.Index.QueryTypeName) || bytes.Equal(parent, g.schema.Index.MutationTypeName) || bytes.Equal(parent, g.schema.Index.SubscriptionTypeName) {
		g.rootFields[fieldName] = struct{}{}
		return
	}
	g.typesFields[string(parent)] = append(g.typesFields[string(parent)], fieldName)
}

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

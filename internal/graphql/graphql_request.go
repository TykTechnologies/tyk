package graphql

import (
	"bytes"
	"strings"

	"github.com/TykTechnologies/graphql-go-tools/pkg/astnormalization"
	"github.com/TykTechnologies/graphql-go-tools/pkg/astvisitor"
	"github.com/TykTechnologies/graphql-go-tools/pkg/operationreport"

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
	stats.Variables = string(g.gqlRequest.Variables)
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

package graphql

import (
	"errors"
	"strings"

	"github.com/TykTechnologies/graphql-go-tools/pkg/astparser"

	"github.com/TykTechnologies/graphql-go-tools/pkg/operationreport"

	"github.com/buger/jsonparser"

	"github.com/TykTechnologies/graphql-go-tools/pkg/ast"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/TykTechnologies/tyk-pump/analytics"
)

type GraphStatsExtractionVisitor struct {
	extractor *graphql.Extractor

	gqlRequest *graphql.Request
	schema     *ast.Document
}

func NewGraphStatsExtractor() *GraphStatsExtractionVisitor {
	extractor := &GraphStatsExtractionVisitor{
		extractor: graphql.NewExtractor(),
	}
	return extractor
}

func (g *GraphStatsExtractionVisitor) GraphErrors(response []byte) ([]string, error) {
	errs := make([]string, 0)
	errBytes, t, _, err := jsonparser.Get(response, "errors")
	// check if the errors key exists in the response
	if err != nil {
		if errors.Is(err, jsonparser.KeyPathNotFoundError) {
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
			errs = append(errs, message)
		}); err != nil {
			return nil, err
		}
	}
	return errs, nil
}

func (g *GraphStatsExtractionVisitor) ExtractStats(rawRequest, response, schema string) (analytics.GraphQLStats, error) {
	var stats analytics.GraphQLStats
	stats.IsGraphQL = true
	var gqlRequest graphql.Request
	if err := graphql.UnmarshalRequest(strings.NewReader(rawRequest), &gqlRequest); err != nil {
		return stats, err
	}
	g.gqlRequest = &gqlRequest

	stats.Variables = string(g.gqlRequest.Variables)

	sh, err := graphql.NewSchemaFromString(schema)
	if err != nil {
		return stats, err
	}
	schemaDoc, opReport := astparser.ParseGraphqlDocumentBytes(sh.Document())
	if opReport.HasErrors() {
		return stats, opReport
	}
	g.schema = &schemaDoc

	requestTypes := make(graphql.RequestTypes)
	var report operationreport.Report
	g.extractor.ExtractFieldsFromRequestSingleOperation(g.gqlRequest, sh, &report, requestTypes)
	if report.HasErrors() {
		return stats, report
	}

	var typesFields = make(map[string][]string)
	var rootFields []string
	for t, fields := range requestTypes {
		isRootOperationType := false
		if t == string(g.schema.Index.QueryTypeName) || t == string(g.schema.Index.MutationTypeName) || t == string(g.schema.Index.SubscriptionTypeName) {
			isRootOperationType = true
		}
		for field := range fields {
			if isRootOperationType {
				rootFields = append(rootFields, field)
			} else {
				typesFields[t] = append(typesFields[t], field)
			}
		}
	}

	stats.Types = typesFields
	stats.RootFields = rootFields
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

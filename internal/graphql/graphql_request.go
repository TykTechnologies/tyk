package graphql

import (
	"github.com/TykTechnologies/graphql-go-tools/pkg/ast"
	"github.com/TykTechnologies/graphql-go-tools/pkg/astparser"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"strings"
)

type GraphRequest struct {
	graphql.Request

	operationRef int
	requestDoc   *ast.Document
	schema       *ast.Document
}

func NewRequestFromBodySchema(rawRequest, schema string) (*GraphRequest, error) {
	var gqlRequest graphql.Request
	if err := graphql.UnmarshalRequest(strings.NewReader(rawRequest), &gqlRequest); err != nil {
		return nil, err
	}

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
		Request:      gqlRequest,
		operationRef: ast.InvalidRef,
		requestDoc:   &requestDoc,
		schema:       &schemaDoc,
	}, nil
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

//func (g *GraphRequest)

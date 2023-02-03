package adapter

import (
	"bytes"
	"fmt"

	"github.com/TykTechnologies/graphql-go-tools/pkg/astprinter"
	"github.com/TykTechnologies/graphql-go-tools/pkg/asyncapi"
	"github.com/TykTechnologies/graphql-go-tools/pkg/operationreport"
	"github.com/TykTechnologies/tyk/apidef"
)

func ImportAsyncAPIDocument(input []byte) (apidef.APIDefinition, error) {
	def := apidef.DummyAPI()

	parsed, err := asyncapi.ParseAsyncAPIDocument(input)
	if err != nil {
		return def, err
	}

	report := operationreport.Report{}
	doc := asyncapi.ImportParsedAsyncAPIDocument(parsed, &report)
	if report.HasErrors() {
		return def, report
	}

	w := &bytes.Buffer{}
	err = astprinter.PrintIndent(doc, nil, []byte("  "), w)
	if err != nil {
		return def, err
	}

	def.Name = fmt.Sprintf("%s - %s", parsed.Info.Title, parsed.Info.Version)
	def.GraphQL.Enabled = true
	def.Active = true
	def.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
	def.GraphQL.Schema = w.String()

	return def, nil
}

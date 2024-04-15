package graphengine

import (
	"fmt"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/graphql"
	"net/http"
)

type ContextRetrieveRequestV2Func func(r *http.Request) *graphql.Request
type ContextStoreRequestV2Func func(r *http.Request, gqlRequest *graphql.Request)

type graphqlGoToolsV2 struct{}

func (g graphqlGoToolsV2) parseSchema(schema string) (*graphql.Schema, error) {
	parsed, err := graphql.NewSchemaFromString(schema)
	if err != nil {
		return nil, err
	}

	normalizeResult, err := parsed.Normalize()
	if err != nil {
		return nil, err
	}

	if !normalizeResult.Successful {
		return nil, fmt.Errorf("error normalizing schema: %w", normalizeResult.Errors)
	}

	return parsed, nil
}

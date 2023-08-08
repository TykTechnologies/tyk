//go:build v52
// +build v52

package graphql

import (
	"context"
	"net/http"

	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/resolve"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
)

type Executor struct {
	Engine       *graphql.ExecutionEngine
	CancelV2     context.CancelFunc
	EngineV2     *graphql.ExecutionEngineV2
	OtelExecutor *OtelGraphqlEngineV2
	HooksV2      struct {
		BeforeFetchHook resolve.BeforeFetchHook
		AfterFetchHook  resolve.AfterFetchHook
	}
	Client          *http.Client
	StreamingClient *http.Client
	Schema          *graphql.Schema
}

func (e *Executor) Execute(reqCtx context.Context, gqlRequest *graphql.Request, w resolve.FlushWriter, execOptions ...graphql.ExecutionOptionsV2) error {
	if e.OtelExecutor != nil {
		return e.OtelExecutor.Execute(reqCtx, gqlRequest, w, execOptions...)
	}

	return e.EngineV2.Execute(reqCtx, gqlRequest, w, execOptions...)
}

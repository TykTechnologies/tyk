package gateway

import (
	"io"
	"net/http"

	gql "github.com/TykTechnologies/tyk-gql/graphql"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/graphengine"
)

type ProxyOnlyGraphQLMiddleware struct {
	*BaseMiddleware
}

func (m *ProxyOnlyGraphQLMiddleware) Name() string {
	return "ProxyOnlyGraphQLMiddleware"
}

func (m *ProxyOnlyGraphQLMiddleware) EnabledForSpec() bool {
	return m.Spec.GraphQL.Enabled
}

func ctxSetGraphQLRequestV4(r *http.Request, gqlRequest *gql.Request) {
	setCtxValue(r, ctx.GraphQLRequest, gqlRequest)
}

func ctxGetGraphQLRequestV4(r *http.Request) (gqlRequest *gql.Request) {
	if v := r.Context().Value(ctx.GraphQLRequest); v != nil {
		if gqlRequest, ok := v.(*gql.Request); ok {
			return gqlRequest
		}
	}
	return nil
}

func (m *ProxyOnlyGraphQLMiddleware) Init() {
	if m.Spec.GraphQL.Version != apidef.GraphQLConfigVersionProxyOnly {
		// Nothing to do. Quit now.
		return
	}

	schema, err := gql.NewSchemaFromString(m.Spec.GraphQL.Schema)
	if err != nil {
		log.Errorf("Error while creating schema from API definition: %v", err)
		return
	}

	normalizationResult, err := schema.Normalize()
	if err != nil {
		log.Errorf("Error while normalizing schema from API definition: %v", err)
	}

	if !normalizationResult.Successful {
		log.Errorf("Schema normalization was not successful. Reason: %v", normalizationResult.Errors)
	}

	m.Spec.GraphEngine = graphengine.NewProxyOnlyEngine(graphengine.ProxyOnlyEngineOptions{
		Logger:        log,
		Schema:        schema,
		ApiDefinition: m.Spec.APIDefinition,
		HttpClient: &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsClientConfig(m.Spec, nil)},
		},
		StreamingClient: &http.Client{
			Timeout:   0,
			Transport: &http.Transport{TLSClientConfig: tlsClientConfig(m.Spec, nil)},
		},
		OpenTelemetry: graphengine.ProxyOnlyEngineOTelConfig{
			Enabled:        m.Gw.GetConfig().OpenTelemetry.Enabled,
			TracerProvider: m.Gw.TracerProvider,
		},
		Injections: graphengine.ProxyOnlyEngineInjections{
			ContextRetrieveRequest: ctxGetGraphQLRequestV4,
			ContextStoreRequest:    ctxSetGraphQLRequestV4,
			SeekReadCloser: func(readCloser io.ReadCloser) (io.ReadCloser, error) {
				body, ok := readCloser.(*nopCloserBuffer)
				if !ok {
					return nil, nil
				}
				_, err := body.Seek(0, io.SeekStart)
				if err != nil {
					return nil, err
				}
				return body, nil
			},
		},
	})
}

func (m *ProxyOnlyGraphQLMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if m.Spec.GraphQL.Version != apidef.GraphQLConfigVersionProxyOnly {
		// Nothing to do. Quit now.
		return nil, 0
	}

	if m.Spec.GraphEngine == nil {
		m.Logger().Error("GraphEngine is not initialized")
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}

	if !m.Spec.GraphEngine.HasSchema() {
		m.Logger().Error("Schema is not created")
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}

	// With current in memory server approach we need body to be readable again
	// as for proxy only API we are sending it as is
	nopCloseRequestBody(r)

	return m.Spec.GraphEngine.ProcessAndStoreGraphQLRequest(w, r)
}

// Interface guard
var _ TykMiddleware = (*ProxyOnlyGraphQLMiddleware)(nil)

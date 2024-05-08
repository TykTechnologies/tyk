package graphengine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/buger/jsonparser"

	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/astparser"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/postprocess"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/graphql"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/introspection"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/operationreport"
	"github.com/TykTechnologies/tyk/apidef"
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

func (g graphqlGoToolsV2) handleIntrospection(schema *graphql.Schema) (res *http.Response, hijacked bool, err error) {
	var (
		introspectionData = struct {
			Data introspection.Data `json:"data"`
		}{}
		report operationreport.Report
	)
	gen := introspection.NewGenerator()
	doc, report := astparser.ParseGraphqlDocumentBytes(schema.Document())
	if report.HasErrors() {
		err = report
		return
	}
	gen.Generate(&doc, &report, &introspectionData.Data)

	var buf bytes.Buffer
	err = json.NewEncoder(&buf).Encode(introspectionData)
	if err != nil {
		return
	}

	res = &http.Response{}
	res.Body = io.NopCloser(&buf)
	res.Header = make(http.Header)
	res.StatusCode = 200

	res.Header.Set("Content-Type", "application/json")
	return
}

func (g graphqlGoToolsV2) headerModifier(outreq *http.Request, additionalHeaders http.Header, variableReplacer TykVariableReplacer) postprocess.HeaderModifier {
	return func(header http.Header) {
		for key := range additionalHeaders {
			if header.Get(key) == "" {
				header.Set(key, additionalHeaders.Get(key))
			}
		}

		for key := range header {
			val := variableReplacer(outreq, header.Get(key), false)
			header.Set(key, val)
		}
	}
}

func (g graphqlGoToolsV2) returnErrorsFromUpstream(proxyOnlyCtx *GraphQLProxyOnlyContextValues, resultWriter *graphql.EngineResultWriter, seekReadCloser SeekReadCloserFunc) error {
	body, err := seekReadCloser(proxyOnlyCtx.upstreamResponse.Body)
	if body == nil {
		// Response body already read by graphql-go-tools, and it's not re-readable. Quit silently.
		return nil
	} else if err != nil {
		return err
	}

	responseBody, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	// graphql-go-tools error message format: {"errors": [...]}
	// Insert the upstream error into the first error message.
	result, err := jsonparser.Set(resultWriter.Bytes(), responseBody, "errors", "[0]", "extensions")
	if err != nil {
		return err
	}
	resultWriter.Reset()
	_, err = resultWriter.Write(result)
	return err
}

type reverseProxyPreHandlerV2 struct {
	ctxRetrieveGraphQLRequest ContextRetrieveRequestV2Func
	apiDefinition             *apidef.APIDefinition
	httpClient                *http.Client
	newReusableBodyReadCloser NewReusableBodyReadCloserFunc
}

func (r *reverseProxyPreHandlerV2) PreHandle(params ReverseProxyParams) (reverseProxyType ReverseProxyType, err error) {
	r.httpClient.Transport = NewGraphQLEngineTransport(
		DetermineGraphQLEngineTransportType(r.apiDefinition),
		params.RoundTripper,
		r.newReusableBodyReadCloser,
	)

	switch {
	case params.IsCORSPreflight:
		return ReverseProxyTypePreFlight, nil
	case params.IsWebSocketUpgrade:
		if params.NeedsEngine {
			return ReverseProxyTypeWebsocketUpgrade, nil
		}
	default:
		gqlRequest := r.ctxRetrieveGraphQLRequest(params.OutRequest)
		if gqlRequest == nil {
			err = errors.New("graphql request is nil")
			return
		}
		gqlRequest.SetHeader(params.OutRequest.Header)

		var isIntrospection bool
		isIntrospection, err = gqlRequest.IsIntrospectionQuery()
		if err != nil {
			return
		}

		if isIntrospection {
			return ReverseProxyTypeIntrospection, nil
		}
		if params.NeedsEngine {
			return ReverseProxyTypeGraphEngine, nil
		}
	}

	return ReverseProxyTypeNone, nil
}

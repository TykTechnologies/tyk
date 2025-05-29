package gateway

import (
	"context"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTraceHttpRequest_toRequest(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const body = `{"foo":"bar"}`
	header := http.Header{}
	header.Add("key", "value")

	tr := traceRequest{
		Request: &traceHttpRequest{Path: "", Method: http.MethodPost, Body: body, Headers: header},
		Spec: &apidef.APIDefinition{
			Proxy: apidef.ProxyConfig{
				ListenPath: "",
			},
		},
		OAS: &oas.OAS{},
	}

	request, err := tr.toRequest(ctx, ts.Gw.GetConfig().IgnoreCanonicalMIMEHeaderKey)
	bodyInBytes, _ := io.ReadAll(request.Body)

	assert.NoError(t, err)
	assert.Equal(t, http.MethodPost, request.Method)
	assert.Equal(t, "", request.URL.Host)
	assert.Equal(t, "", request.URL.Path)
	assert.Equal(t, header, request.Header)
	assert.Equal(t, string(bodyInBytes), body)
}

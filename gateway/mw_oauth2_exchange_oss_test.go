//go:build !ee && !dev

package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNoopOAuth2Exchange_OSSBuild covers the OSS shim that stands in for the EE
// token-exchange middleware: it must never run the exchange, always pass the
// request through, and log once when an operator ships a tokenExchange config
// on a build that cannot honour it.
func TestNoopOAuth2Exchange_OSSBuild(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(ts.Close)

	oasJSON := buildOAuth2ExchangeAPI("https://idp", "https://idp/token", "/te-oss/")
	specs := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.IsOAS = true
		require.NoError(t, spec.OAS.UnmarshalJSON([]byte(oasJSON)))
		spec.OAS.ExtractTo(spec.APIDefinition)
		spec.APIID = "te-oss"
		spec.Proxy.ListenPath = "/te-oss/"
		spec.UseKeylessAccess = true
	})
	require.Len(t, specs, 1)

	mw := getOAuth2ExchangeMw(&BaseMiddleware{Spec: specs[0], Gw: ts.Gw})
	require.NotNil(t, mw)
	assert.Equal(t, "NoopOAuth2Exchange", mw.Name())

	t.Run("ProcessRequest is a pass-through no-op", func(t *testing.T) {
		err, code := mw.ProcessRequest(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/te-oss/x", nil), nil)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, code)
	})

	t.Run("EnabledForSpec stays false even with tokenExchange enabled, and is idempotent", func(t *testing.T) {
		assert.False(t, mw.EnabledForSpec(), "OSS build must never enable token exchange")
		assert.False(t, mw.EnabledForSpec(), "second call (logOnce already fired) is still false")
	})

	t.Run("non-OAS spec short-circuits to false", func(t *testing.T) {
		plain := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.APIID = "te-oss-plain"
			spec.Proxy.ListenPath = "/te-oss-plain/"
			spec.UseKeylessAccess = true
		})
		require.Len(t, plain, 1)
		plainMw := getOAuth2ExchangeMw(&BaseMiddleware{Spec: plain[0], Gw: ts.Gw})
		assert.False(t, plainMw.EnabledForSpec())
	})
}

//go:build ee || dev

package gateway

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
)

const streamWithBentoCORSTemplate = `
streams:
  test:
    input:
      http_server:
        path: /post
        timeout: 1s
    output:
      http_server:
        ws_path: /subscribe
        stream_path: /get/stream
        cors:
          enabled: true
          allowed_origins:
            - https://good.example
`

func TestStreamsWebSocket_OriginCheck(t *testing.T) {
	const (
		apiName  = "ws-origin-stream"
		attacker = "http://attacker.example"
		good     = "https://good.example"
	)

	newGateway := func(t *testing.T, allowUnsafe bool) *Test {
		t.Helper()
		ts := StartTest(func(conf *config.Config) {
			conf.Streaming.Enabled = true
			conf.AllowUnsafeWebSocketOrigin = allowUnsafe
		})
		t.Cleanup(ts.Close)
		return ts
	}

	loadAPI := func(t *testing.T, ts *Test, streamConfig string, cors apidef.CORSConfig) *APISpec {
		t.Helper()
		oasAPI, err := setupOASForStreamAPI(streamConfig)
		require.NoError(t, err)
		return ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.APIID = apiName
			spec.Proxy.ListenPath = "/" + apiName
			spec.UseKeylessAccess = true
			spec.IsOAS = true
			spec.CORS = cors
			spec.OAS = oasAPI
			spec.OAS.Fill(*spec.APIDefinition)
		})[0]
	}

	wsURL := func(ts *Test) string {
		return strings.Replace(ts.URL, "http://", "ws://", 1) + "/" + apiName + "/subscribe"
	}

	t.Run("without CORS", func(t *testing.T) {
		ts := newGateway(t, false)
		api := loadAPI(t, ts, bentoHTTPServerTemplate, apidef.CORSConfig{})

		t.Run("no origin connects", func(t *testing.T) {
			assert.Equal(t, http.StatusSwitchingProtocols, dialWebSocket(t, wsURL(ts), "", nil))
		})

		t.Run("own origin connects and receives messages", func(t *testing.T) {
			headers := http.Header{"Origin": {ts.URL}}
			conn, resp, err := websocket.DefaultDialer.Dial(wsURL(ts), headers)
			require.NoError(t, err)
			t.Cleanup(func() { _ = conn.Close() })
			assert.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)

			publish, err := http.Post(fmt.Sprintf("%s/%s/post", ts.URL, apiName), "application/json",
				bytes.NewReader([]byte(`{"secret":"data-1"}`)))
			require.NoError(t, err)
			_ = publish.Body.Close()

			require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
			_, msg, err := conn.ReadMessage()
			require.NoError(t, err)
			assert.Equal(t, `{"secret":"data-1"}`, string(msg))
		})

		t.Run("other origin is refused and logged", func(t *testing.T) {
			hook := log.GetTestHook(t)
			assert.Equal(t, http.StatusForbidden, dialWebSocket(t, wsURL(ts), attacker, nil))
			assert.True(t, refusalLogged(hook, api.APIID, attacker), "refusal is logged with the API ID and origin")
		})
	})

	t.Run("with Tyk CORS", func(t *testing.T) {
		ts := newGateway(t, false)
		loadAPI(t, ts, bentoHTTPServerTemplate, apidef.CORSConfig{Enable: true, AllowedOrigins: []string{good}})

		t.Run("allowed origin connects", func(t *testing.T) {
			assert.Equal(t, http.StatusSwitchingProtocols, dialWebSocket(t, wsURL(ts), good, nil))
		})
		t.Run("other origin is refused", func(t *testing.T) {
			assert.Equal(t, http.StatusForbidden, dialWebSocket(t, wsURL(ts), attacker, nil))
		})
	})

	t.Run("with Bento CORS only", func(t *testing.T) {
		ts := newGateway(t, false)
		loadAPI(t, ts, streamWithBentoCORSTemplate, apidef.CORSConfig{})

		t.Run("origin that only Bento allows is refused", func(t *testing.T) {
			assert.Equal(t, http.StatusForbidden, dialWebSocket(t, wsURL(ts), good, nil))
		})
		t.Run("other origin is refused", func(t *testing.T) {
			assert.Equal(t, http.StatusForbidden, dialWebSocket(t, wsURL(ts), attacker, nil))
		})
	})

	t.Run("with Bento CORS and Tyk CORS", func(t *testing.T) {
		ts := newGateway(t, false)
		loadAPI(t, ts, streamWithBentoCORSTemplate, apidef.CORSConfig{Enable: true, AllowedOrigins: []string{good, attacker}})

		t.Run("origin both allow connects", func(t *testing.T) {
			assert.Equal(t, http.StatusSwitchingProtocols, dialWebSocket(t, wsURL(ts), good, nil))
		})
		t.Run("origin that Bento refuses is still refused", func(t *testing.T) {
			assert.Equal(t, http.StatusForbidden, dialWebSocket(t, wsURL(ts), attacker, nil))
		})
	})

	t.Run("with allow_unsafe_websocket_origin", func(t *testing.T) {
		ts := newGateway(t, true)
		loadAPI(t, ts, bentoHTTPServerTemplate, apidef.CORSConfig{})

		t.Run("other origin connects", func(t *testing.T) {
			assert.Equal(t, http.StatusSwitchingProtocols, dialWebSocket(t, wsURL(ts), attacker, nil))
		})
	})
}

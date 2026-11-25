package gateway

import (
	"net/http"
	"strings"
	"testing"

	gqlwebsocket "github.com/TykTechnologies/graphql-go-tools/pkg/subscription/websocket"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
	tyklog "github.com/TykTechnologies/tyk/log"
)

func TestAfterConfSetup_WarnsWhenWebSocketOriginCheckIsOff(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(ts.Close)

	hook := log.GetTestHook(t)

	warned := func() bool {
		return hook.SomeBy(func(entry *logrus.Entry) bool {
			return entry.Level == logrus.WarnLevel && strings.Contains(entry.Message, "allow_unsafe_websocket_origin")
		})
	}

	t.Run("off by default, no warning", func(t *testing.T) {
		require.NoError(t, ts.Gw.afterConfSetup())
		assert.False(t, ts.Gw.GetConfig().AllowUnsafeWebSocketOrigin)
		assert.False(t, warned())
	})

	t.Run("on, warning logged", func(t *testing.T) {
		ts.Gw.SetConfig(func() config.Config {
			conf := ts.Gw.GetConfig()
			conf.AllowUnsafeWebSocketOrigin = true
			return conf
		}())
		require.NoError(t, ts.Gw.afterConfSetup())
		assert.True(t, warned())
	})
}

// dialWebSocket opens a WebSocket to wsURL with the given Origin (none when
// empty) and returns the handshake status code.
func dialWebSocket(t *testing.T, wsURL, origin string, extra http.Header) int {
	t.Helper()

	headers := http.Header{}
	for name, values := range extra {
		headers[name] = values
	}
	if origin != "" {
		headers.Set("Origin", origin)
	}

	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, headers)
	if conn != nil {
		t.Cleanup(func() { _ = conn.Close() })
	}
	if resp == nil {
		require.NoError(t, err)
		return 0
	}
	return resp.StatusCode
}

func refusalLogged(hook *tyklog.Hook, apiID, origin string) bool {
	return hook.SomeBy(func(entry *logrus.Entry) bool {
		return entry.Data["api_id"] == apiID && entry.Data["origin"] == origin &&
			strings.Contains(entry.Message, "WebSocket handshake refused")
	})
}

func TestGraphQLWebSocket_OriginCheck(t *testing.T) {
	const (
		attacker = "http://attacker.example"
		good     = "https://good.example"
	)
	graphqlWS := http.Header{header.SecWebSocketProtocol: {string(gqlwebsocket.ProtocolGraphQLTransportWS)}}

	newGateway := func(t *testing.T, allowUnsafe bool) *Test {
		t.Helper()
		ts := StartTest(func(conf *config.Config) {
			conf.HttpServerOptions.EnableWebSockets = true
			conf.AllowUnsafeWebSocketOrigin = allowUnsafe
		})
		t.Cleanup(ts.Close)
		return ts
	}

	loadAPI := func(ts *Test, cors apidef.CORSConfig) *APISpec {
		return ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.APIID = "graphql-ws-origin"
			spec.UseKeylessAccess = true
			spec.Proxy.ListenPath = "/"
			spec.GraphQL.Enabled = true
			spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly
			spec.GraphQL.Version = apidef.GraphQLConfigVersion2
			spec.CORS = cors
		})[0]
	}

	t.Run("without CORS", func(t *testing.T) {
		ts := newGateway(t, false)
		api := loadAPI(ts, apidef.CORSConfig{})
		wsURL := strings.Replace(ts.URL, "http://", "ws://", 1)
		ownOrigin := ts.URL

		t.Run("no origin connects", func(t *testing.T) {
			assert.Equal(t, http.StatusSwitchingProtocols, dialWebSocket(t, wsURL, "", graphqlWS))
		})
		t.Run("own origin connects", func(t *testing.T) {
			assert.Equal(t, http.StatusSwitchingProtocols, dialWebSocket(t, wsURL, ownOrigin, graphqlWS))
		})
		t.Run("other origin is refused and logged", func(t *testing.T) {
			hook := log.GetTestHook(t)
			assert.Equal(t, http.StatusForbidden, dialWebSocket(t, wsURL, attacker, graphqlWS))
			assert.True(t, refusalLogged(hook, api.APIID, attacker), "refusal is logged with the API ID and origin")
		})
	})

	t.Run("with CORS", func(t *testing.T) {
		ts := newGateway(t, false)
		loadAPI(ts, apidef.CORSConfig{Enable: true, AllowedOrigins: []string{good}})
		wsURL := strings.Replace(ts.URL, "http://", "ws://", 1)

		t.Run("allowed origin connects", func(t *testing.T) {
			assert.Equal(t, http.StatusSwitchingProtocols, dialWebSocket(t, wsURL, good, graphqlWS))
		})
		t.Run("other origin is refused", func(t *testing.T) {
			assert.Equal(t, http.StatusForbidden, dialWebSocket(t, wsURL, attacker, graphqlWS))
		})
	})

	t.Run("with allow_unsafe_websocket_origin", func(t *testing.T) {
		ts := newGateway(t, true)
		loadAPI(ts, apidef.CORSConfig{})
		wsURL := strings.Replace(ts.URL, "http://", "ws://", 1)

		t.Run("other origin connects", func(t *testing.T) {
			assert.Equal(t, http.StatusSwitchingProtocols, dialWebSocket(t, wsURL, attacker, graphqlWS))
		})
	})
}

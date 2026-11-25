//go:build ee || dev

package gateway

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
)

func TestKafkaResetAuditCredentialPrincipalIsStableAndSeparated(t *testing.T) {
	shared := kafkaResetAuditActorHash("gateway-secret", "control-api-owner")
	require.Len(t, shared, 64)
	_, err := hex.DecodeString(shared)
	require.NoError(t, err)
	require.Equal(t, shared, kafkaResetAuditActorHash("gateway-secret", "control-api-owner"), "equivalent Gateway configurations must derive the same principal")
	require.NotEqual(t, shared, kafkaResetAuditActorHash("gateway-secret", "dedicated-reset", "ref", "dedicated-secret"))
	require.NotContains(t, shared, "gateway-secret")
	require.NotContains(t, shared, "dedicated-secret")
}

func TestKafkaResetAuditCredentialPrincipalUsesInjectiveFieldEncoding(t *testing.T) {
	// Delimiter concatenation aliases these tuples as "ref\x00credential".
	// Length-prefixing the independently configured ref and credential must not.
	first := kafkaResetAuditActorHash("gateway-secret", "dedicated-reset", "ref", "credential\x00suffix")
	second := kafkaResetAuditActorHash("gateway-secret", "dedicated-reset", "ref\x00credential", "suffix")
	require.NotEqual(t, first, second)
	require.Equal(t, first, kafkaResetAuditActorHash("gateway-secret", "dedicated-reset", "ref", "credential\x00suffix"))
}

func TestKafkaOffsetResetDedicatedControlCredential(t *testing.T) {
	gw := &Gateway{}
	cfg := config.Config{Secrets: map[string]string{"reset-control": "dedicated-reset-secret"}}
	cfg.KafkaOffsetResetAuthorization.SecretRef = "reset-control"
	gw.SetConfig(cfg)
	router := mux.NewRouter()
	registerStreamingControlEndpoints(router, gw)
	path := "/streams/api/stream/kafka/api_stream_input/offset/reset/plan"

	for _, credential := range []string{"", "wrong"} {
		request := httptest.NewRequest(http.MethodPost, path, nil)
		if credential != "" {
			request.Header.Set(kafkaOffsetResetAuthorizationHeader, credential)
		}
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		require.Equal(t, http.StatusForbidden, response.Code)
	}
	request := httptest.NewRequest(http.MethodPost, path, nil)
	request.Header.Set(kafkaOffsetResetAuthorizationHeader, "dedicated-reset-secret")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	require.Equal(t, http.StatusBadRequest, response.Code, "dedicated credential passes authorization and reaches request validation")
}

func TestKafkaOffsetResetDedicatedCredentialFailsClosedForMissingSecretRef(t *testing.T) {
	gw := &Gateway{}
	cfg := config.Config{}
	cfg.KafkaOffsetResetAuthorization.SecretRef = "missing"
	gw.SetConfig(cfg)
	router := mux.NewRouter()
	registerStreamingControlEndpoints(router, gw)
	request := httptest.NewRequest(http.MethodPost, "/streams/api/stream/kafka/api_stream_input/offset/reset/plan", nil)
	request.Header.Set(kafkaOffsetResetAuthorizationHeader, "anything")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	require.Equal(t, http.StatusForbidden, response.Code)
}

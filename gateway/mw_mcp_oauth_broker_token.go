package gateway

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/service/core"
)

type mcpOAuthBearerProvider struct {
	accessToken string
}

func (p mcpOAuthBearerProvider) Fill(r *http.Request) {
	r.Header.Set(header.Authorization, "Bearer "+p.accessToken)
}

// MCPOAuthBrokerTokenMiddleware validates Gateway-issued resource tokens and
// installs the associated upstream bearer for the outbound proxy request.
// The inbound header is left untouched so the upstream credential cannot enter
// request analytics or logs.
type MCPOAuthBrokerTokenMiddleware struct {
	*BaseMiddleware
}

func (m *MCPOAuthBrokerTokenMiddleware) Name() string { return "MCPOAuthBrokerTokenMiddleware" }

func (m *MCPOAuthBrokerTokenMiddleware) EnabledForSpec() bool {
	return m != nil && m.Spec != nil && m.Spec.MCP != nil && m.Spec.MCP.OAuthBroker != nil && m.Spec.MCP.OAuthBroker.Enabled
}

func (m *MCPOAuthBrokerTokenMiddleware) ProcessRequest(_ http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	values := r.Header.Values(header.Authorization)
	if len(values) != 1 {
		return errors.New("invalid MCP OAuth access token"), http.StatusUnauthorized
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) != 43 {
		return errors.New("invalid MCP OAuth access token"), http.StatusUnauthorized
	}
	broker := newMCPOAuthBroker(m.Gw, m.Spec)
	var grant mcpOAuthTokenGrant
	found, err := broker.getRecord(r.Context(), broker.accessKey(parts[1]), &grant)
	if err != nil {
		return errors.New("MCP OAuth token store unavailable"), http.StatusServiceUnavailable
	}
	if !found || !broker.validGrant(grant, grant.DownstreamClientID, broker.config.PublicResource) ||
		grant.ExpiresAt <= time.Now().Unix() || grant.UpstreamExpiresAt <= time.Now().Unix() || grant.UpstreamAccessToken == "" {
		return errors.New("invalid MCP OAuth access token"), http.StatusUnauthorized
	}
	var revoked map[string]bool
	if found, err := broker.getRecord(r.Context(), broker.revokedFamilyKey(grant.FamilyID), &revoked); err != nil {
		return errors.New("MCP OAuth token store unavailable"), http.StatusServiceUnavailable
	} else if found {
		return errors.New("invalid MCP OAuth access token"), http.StatusUnauthorized
	}
	core.SetUpstreamAuth(r, mcpOAuthBearerProvider{accessToken: grant.UpstreamAccessToken})
	return nil, http.StatusOK
}

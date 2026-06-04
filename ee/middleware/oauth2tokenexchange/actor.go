//go:build ee || dev

package oauth2tokenexchange

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/oauth2common"
	tyktime "github.com/TykTechnologies/tyk/internal/time"
)

const (
	// DefaultActorTokenHeader is the request header read when
	// actorToken.source==header and no explicit name is configured.
	DefaultActorTokenHeader = "X-Actor-Token"

	// DefaultActorTokenTTL caches a CC actor token when the IdP returns
	// no usable expires_in.
	DefaultActorTokenTTL = 5 * time.Minute

	// ActorTokenTTLSafetyMargin is trimmed off the IdP-reported lifetime
	// so a cached actor token is never replayed right at its expiry.
	ActorTokenTTLSafetyMargin = 30 * time.Second
)

// actorSF coalesces concurrent first-misses for the same CC actor-token key.
var actorSF singleflight.Group

// actorTokenCache is a minimal in-process TTL cache for client_credentials
// actor tokens. Keyed by ActorCacheKey (tokenEndpoint+clientId+scopes), which
// is non-secret operator config.
type actorTokenCache struct {
	mu      sync.RWMutex
	entries map[string]actorCacheEntry
}

type actorCacheEntry struct {
	token  string
	expiry time.Time
}

func newActorTokenCache() *actorTokenCache {
	return &actorTokenCache{entries: make(map[string]actorCacheEntry)}
}

func (c *actorTokenCache) get(key string) (string, bool) {
	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expiry) {
		return "", false
	}
	return e.token, true
}

func (c *actorTokenCache) put(key, token string, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	c.entries[key] = actorCacheEntry{token: token, expiry: time.Now().Add(ttl)}
	c.mu.Unlock()
}

// acquireActorToken returns (actorToken, actorID) for the matched provider's
// actorToken config, or ("", OAuth2ActorImpersonation) when no actor token is
// configured. Errors only when a source is configured but the token can't be
// obtained — CC flow fails, or `header` source is `required: true` but absent.
func (m *Middleware) acquireActorToken(r *http.Request, provider *oas.OAuth2TokenExchangeProvider) (string, string, error) {
	at := provider.ActorToken
	if at == nil {
		return "", oas.OAuth2ActorImpersonation, nil
	}
	switch at.Source {
	case oas.OAuth2ActorSourceClientCredentials:
		if at.ClientCredentials == nil {
			return "", "", errors.New("actorToken.source=client_credentials but clientCredentials block is missing")
		}
		token, err := m.getOrAcquireActorTokenViaCC(r.Context(), at.ClientCredentials, provider.Timeout, provider.Name)
		if err != nil {
			return "", "", err
		}
		return token, at.ClientCredentials.ClientID, nil
	case oas.OAuth2ActorSourceHeader:
		hdr, strip, required := actorHeaderSettings(at.Header)
		raw := r.Header.Get(hdr)
		if raw == "" {
			if required {
				return "", "", &oauth2common.MissingActorTokenError{Header: hdr}
			}
			return "", oas.OAuth2ActorImpersonation, nil
		}
		if strip {
			r.Header.Del(hdr)
		}
		return raw, oauth2common.HashActorID(raw), nil
	case oas.OAuth2ActorSourceStatic:
		if at.Static == nil || at.Static.Token == "" {
			return "", "", errors.New("actorToken.source=static but static.token is empty")
		}
		return at.Static.Token, oauth2common.HashActorID(at.Static.Token), nil
	default:
		return "", "", fmt.Errorf("unsupported actorToken.source %q", at.Source)
	}
}

// maybeStripActorHeader removes the configured actor-token header from the
// proxied request when source==header and strip!=false. Called on the success
// paths so the upstream never sees the actor token, even on a cache hit (where
// acquireActorToken's strip branch isn't reached).
func (m *Middleware) maybeStripActorHeader(r *http.Request, provider *oas.OAuth2TokenExchangeProvider) {
	at := provider.ActorToken
	if at == nil || at.Source != oas.OAuth2ActorSourceHeader {
		return
	}
	hdr, strip, _ := actorHeaderSettings(at.Header)
	if strip {
		r.Header.Del(hdr)
	}
}

// actorHeaderSettings resolves header name/strip/required with their defaults
// (X-Actor-Token, strip=true, required=true).
func actorHeaderSettings(h *oas.OAuth2ActorHeader) (name string, strip, required bool) {
	name, strip, required = DefaultActorTokenHeader, true, true
	if h != nil {
		if h.Name != "" {
			name = h.Name
		}
		if h.Strip != nil {
			strip = *h.Strip
		}
		if h.Required != nil {
			required = *h.Required
		}
	}
	return name, strip, required
}

// getOrAcquireActorTokenViaCC returns a cached CC actor token or runs the CC
// flow against the configured endpoint. Concurrent first-misses for the same
// key are coalesced via singleflight.
func (m *Middleware) getOrAcquireActorTokenViaCC(ctx context.Context, cc *oas.OAuth2ActorClientCredentials, timeout tyktime.ReadableDuration, providerName string) (string, error) {
	key := oauth2common.ActorCacheKey(cc.TokenEndpoint, cc.ClientID, cc.Scopes)
	if m.actorCache != nil {
		if cached, ok := m.actorCache.get(key); ok {
			// Served from the actor-token cache: no IdP round-trip, so the
			// acquisition metric is not re-incremented (the counter reads
			// actual IdP load).
			return cached, nil
		}
	}
	start := time.Now()
	v, err, _ := actorSF.Do(key, func() (interface{}, error) {
		if m.actorCache != nil {
			if cached, ok := m.actorCache.get(key); ok {
				return cached, nil
			}
		}
		return m.fetchActorTokenViaCC(ctx, cc, key, timeout)
	})
	m.recordActor(ctx, providerName, time.Since(start), err)
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

// recordActor records one client-credentials actor-token acquisition on the
// observability layer's actor instruments. A no-op when no Base is wired (unit
// tests that exercise acquisition without metrics). The outcome is ok unless
// the acquisition failed (idp_error).
func (m *Middleware) recordActor(ctx context.Context, providerName string, dur time.Duration, err error) {
	if m.Base == nil {
		return
	}
	outcome := oauth2common.OutcomeOK
	if err != nil {
		outcome = oauth2common.OutcomeIdPError
	}
	m.Base.RecordActorAcquisition(ctx, string(outcome), providerName, dur)
}

// fetchActorTokenViaCC performs the CC HTTP call and populates the cache. ctx
// is the inbound request context — a cancelled inbound request cancels this too.
func (m *Middleware) fetchActorTokenViaCC(ctx context.Context, cc *oas.OAuth2ActorClientCredentials, cacheKey string, timeout tyktime.ReadableDuration) (string, error) {
	form := url.Values{}
	form.Set(oas.OAuth2FormGrantType, oas.OAuth2GrantTypeClientCredentials)
	if len(cc.Scopes) > 0 {
		form.Set(oas.OAuth2FormScope, strings.Join(cc.Scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cc.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("building actor CC request: %w", err)
	}
	req.Header.Set(header.ContentType, header.ApplicationFormURLEncoded)
	req.Header.Set(header.Accept, header.ApplicationJSON)
	if cc.ClientID != "" {
		req.SetBasicAuth(cc.ClientID, cc.ClientSecret)
	}

	client := oauth2common.NewIdPHTTPClient(EffectiveIdPTimeout(time.Duration(timeout)))
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("actor CC call failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, oauth2common.MaxIdPResponseBytes))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Sanitize the IdP body before embedding in the error chain — a
		// misconfigured IdP that echoes request bytes would otherwise leak
		// the inbound bearer into logs via downstream WithError(err).
		idpErr, idpDesc := oauth2common.DecodeIdPError(body)
		return "", fmt.Errorf("actor CC call returned status %d: %s: %s", resp.StatusCode, idpErr, idpDesc)
	}
	var parsed struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("decoding actor CC response: %w", err)
	}
	if parsed.AccessToken == "" {
		return "", errors.New("actor CC response missing access_token")
	}
	ttl := time.Duration(parsed.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = DefaultActorTokenTTL
	}
	if m.actorCache != nil {
		m.actorCache.put(cacheKey, parsed.AccessToken, ttl-ActorTokenTTLSafetyMargin)
	}
	return parsed.AccessToken, nil
}

package gateway

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/gorilla/mux"

	"github.com/TykTechnologies/tyk/config"
)

const (
	jwksMinTTL          = 10 * time.Second
	jwksKidMissCooldown = 30 * time.Second
	jwksFetchTimeout    = 15 * time.Second
	jwksMaxBodyBytes    = 1 << 20
)

var errJWKSBackoff = errors.New("jwks fetch in failure backoff")

type ttlSource string

const (
	ttlFromRecord  ttlSource = "record"
	ttlFromDefault ttlSource = "default"
	ttlFromFloor   ttlSource = "floor"
)

func jwksDefaultTTL(cfg config.Config) time.Duration {
	if cfg.JWKS.Cache.Timeout > 0 {
		return time.Duration(cfg.JWKS.Cache.Timeout) * time.Second
	}
	return externalOAuthJWKCacheExpiration * time.Second
}

// An invalid value yields the default TTL together with a non-nil err.
func (i IdP) jwksTTL(gwDefault time.Duration) (ttl time.Duration, source ttlSource, err error) {
	ttl, source = gwDefault, ttlFromDefault
	if i.JWKSCacheTimeout != "" {
		d, perr := time.ParseDuration(i.JWKSCacheTimeout)
		if perr == nil && d > 0 {
			ttl, source = d, ttlFromRecord
		} else {
			err = fmt.Errorf("invalid jwks_cache_timeout %q, using the gateway default", i.JWKSCacheTimeout)
		}
	}
	if ttl < jwksMinTTL {
		ttl, source = jwksMinTTL, ttlFromFloor
	}
	return ttl, source, err
}

type jwksEntry struct {
	url string
	ttl time.Duration

	cached      atomic.Pointer[cachedJWKS]
	lastSuccess atomic.Int64 // unix ns; atomic so the unknown-kid path takes no lock

	mu         sync.Mutex
	gen        uint64 // a fetch stores its result only if gen is unchanged
	inflight   *jwksFetch
	retryAfter time.Time
	backoff    *backoff.ExponentialBackOff
}

func newJWKSEntry(url string, ttl time.Duration) *jwksEntry {
	return &jwksEntry{url: url, ttl: ttl, backoff: backoff.NewExponentialBackOff(
		backoff.WithInitialInterval(time.Second),
		backoff.WithMaxInterval(30*time.Second),
		backoff.WithMaxElapsedTime(0), // keep retrying while requests arrive
	)}
}

type cachedJWKS struct {
	keys    map[string]any
	expires time.Time
}

type jwksFetch struct {
	done chan struct{}
	keys map[string]any
	err  error
}

func (e *jwksEntry) key(ctx context.Context, f *jwksFetcher, kid string) any {
	now := time.Now()
	if c := e.cached.Load(); c != nil && now.Before(c.expires) {
		if key, ok := c.keys[kid]; ok {
			return key
		}
		if now.UnixNano()-e.lastSuccess.Load() < int64(jwksKidMissCooldown) {
			f.recordKidMiss(ctx, "cooldown")
			return nil
		}
		f.recordKidMiss(ctx, "refetched")
	}
	keys, err := e.fetch(ctx, f)
	if err != nil {
		return nil
	}
	return keys[kid]
}

func (e *jwksEntry) fetch(ctx context.Context, f *jwksFetcher) (map[string]any, error) {
	e.mu.Lock()
	if time.Now().Before(e.retryAfter) {
		e.mu.Unlock()
		return nil, errJWKSBackoff
	}
	fl := e.inflight
	if fl == nil {
		fl = &jwksFetch{done: make(chan struct{})}
		e.inflight = fl
		go e.run(f, fl, e.gen)
	}
	e.mu.Unlock()

	select {
	case <-fl.done:
		return fl.keys, fl.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (e *jwksEntry) run(f *jwksFetcher, fl *jwksFetch, gen uint64) {
	keys, err := f.fetch(e.url)
	now := time.Now()

	e.mu.Lock()
	switch {
	case err != nil:
		e.retryAfter = now.Add(e.backoff.NextBackOff())
	case e.gen == gen:
		e.cached.Store(&cachedJWKS{keys: keys, expires: now.Add(e.ttl)})
		e.lastSuccess.Store(now.UnixNano())
		e.backoff.Reset()
		e.retryAfter = time.Time{}
	}
	e.inflight = nil
	e.mu.Unlock()

	fl.keys, fl.err = keys, err
	close(fl.done)
}

// Bumping gen stops a fetch already in flight from storing its result.
func (e *jwksEntry) flush() {
	e.mu.Lock()
	e.gen++
	e.cached.Store(nil)
	e.lastSuccess.Store(0)
	e.mu.Unlock()
}

type jwksFetcher struct {
	gw     *Gateway
	once   sync.Once
	client *http.Client
}

func (f *jwksFetcher) httpClient() *http.Client {
	f.once.Do(func() {
		if c, err := NewExternalHTTPClientFactory(f.gw).CreateJWKClient(); err == nil {
			f.client = c
			return
		}
		f.client = &http.Client{
			Timeout: jwksFetchTimeout,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: f.gw.GetConfig().JWTSSLInsecureSkipVerify},
				TLSHandshakeTimeout: 10 * time.Second,
				IdleConnTimeout:     30 * time.Second,
			},
		}
	})
	return f.client
}

func (f *jwksFetcher) fetch(url string) (map[string]any, error) {
	start := time.Now()
	keys, outcome, err := f.get(url)
	if err != nil {
		f.gw.logJWKError(log.WithField("prefix", "idp-registry"), url, err)
	}
	if f.gw.MetricInstruments != nil {
		f.gw.MetricInstruments.RecordJWKSFetch(context.Background(), "registry", outcome, time.Since(start))
	}
	return keys, err
}

func (f *jwksFetcher) get(url string) (map[string]any, string, error) {
	resp, err := f.httpClient().Get(url)
	if err != nil {
		return nil, "error", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "error", fmt.Errorf("jwks fetch: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, jwksMaxBodyBytes+1))
	if err != nil {
		return nil, "error", err
	}
	if len(body) > jwksMaxBodyBytes {
		return nil, "error", fmt.Errorf("jwks fetch: body exceeds %d bytes", jwksMaxBodyBytes)
	}

	set, err := parseJWK(body)
	if err == nil {
		keys := make(map[string]any, len(set.Keys))
		for _, k := range set.Keys {
			if _, dup := keys[k.KeyID]; !dup {
				keys[k.KeyID] = k.Key
			}
		}
		return keys, "ok", nil
	}
	if keys := legacyKeysFromJWKS(body); len(keys) > 0 {
		return keys, "legacy", nil
	}
	return nil, "error", err
}

// legacyKeysFromJWKS indexes the x5c keys of a set go-jose cannot parse.
func legacyKeysFromJWKS(body []byte) map[string]any {
	var set JWKs
	if json.Unmarshal(body, &set) != nil {
		return nil
	}
	keys := map[string]any{}
	for _, k := range set.Keys {
		if _, dup := keys[k.KID]; dup {
			continue
		}
		if key, err := legacyKeyFromJWK(k); err == nil {
			keys[k.KID] = key
		}
	}
	return keys
}

func (f *jwksFetcher) recordKidMiss(ctx context.Context, result string) {
	if f.gw.MetricInstruments != nil {
		f.gw.MetricInstruments.RecordJWKSKidMiss(ctx, result)
	}
}

// clientIdPNotice is the {"org_id","client_idp_id"} payload the Dashboard sends
// for client IdP notifications.
type clientIdPNotice struct {
	OrgID       string `json:"org_id"`
	ClientIdPID string `json:"client_idp_id"`
}

func (gw *Gateway) flushClientIdPJWKS(orgID, idpID string) {
	if gw.idpRegistry != nil {
		gw.idpRegistry.flushJWKS(idpKey{orgID, idpID})
	}
}

func (gw *Gateway) handleClientIdPJWKSFlushNotice(payload string) {
	var n clientIdPNotice
	if err := json.Unmarshal([]byte(payload), &n); err != nil || n.OrgID == "" || n.ClientIdPID == "" {
		log.WithField("payload", payload).Warn("Ignoring malformed client IdP JWKS flush notice")
		return
	}
	gw.flushClientIdPJWKS(n.OrgID, n.ClientIdPID)
}

func (gw *Gateway) invalidateClientIdPJWKSCache(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	gw.flushClientIdPJWKS(vars["orgID"], vars["idpID"])
	doJSONWrite(w, http.StatusOK, apiOk("cache invalidated"))
}

func (gw *Gateway) invalidateAllClientIdPJWKSCaches(w http.ResponseWriter, _ *http.Request) {
	if gw.idpRegistry != nil {
		gw.idpRegistry.flushAllJWKS()
	}
	doJSONWrite(w, http.StatusOK, apiOk("cache invalidated"))
}

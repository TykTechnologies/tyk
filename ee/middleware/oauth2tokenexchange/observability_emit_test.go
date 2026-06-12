//go:build ee || dev

package oauth2tokenexchange

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/internal/oauth2common"
)

// --- fakes ---

type recordedMetric struct {
	outcome  string
	provider string
	duration time.Duration
}

type recordedEvent struct {
	name apidef.TykEvent
	meta map[string]interface{}
}

type fakeBase struct {
	logger    *logrus.Entry
	metrics   []recordedMetric
	cacheHits []string
	events    []recordedEvent
}

func newFakeBase() *fakeBase {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return &fakeBase{logger: logrus.NewEntry(l)}
}

func (f *fakeBase) Logger() *logrus.Entry { return f.logger }

func (f *fakeBase) FireEvent(name apidef.TykEvent, meta interface{}) {
	m, _ := meta.(map[string]interface{})
	f.events = append(f.events, recordedEvent{name: name, meta: m})
}

func (f *fakeBase) RecordExchangeMetric(_ context.Context, outcome, provider string, d time.Duration) {
	f.metrics = append(f.metrics, recordedMetric{outcome: outcome, provider: provider, duration: d})
}

func (f *fakeBase) RecordExchangeCacheHit(_ context.Context, provider string) {
	f.cacheHits = append(f.cacheHits, provider)
}

// --- helpers ---

func installRecorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(prev) })
	return sr
}

// idpToken returns a signed JWT carrying the given azp, so the exchanged-token
// azp can be read back by the observability path.
func idpToken(t *testing.T, azp string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{oas.OAuth2ClaimAzp: azp})
	s, err := tok.SignedString([]byte("test-secret"))
	require.NoError(t, err)
	return s
}

func okIdP(t *testing.T, delay time.Duration, azp string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(delay)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": idpToken(t, azp),
			"expires_in":   3600,
		})
	}))
}

func erroringIdP() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "subject token expired",
		})
	}))
}

func provider(name, endpoint string, cacheEnabled bool) oas.OAuth2TokenExchangeProvider {
	p := oas.OAuth2TokenExchangeProvider{
		Name:          name,
		Issuers:       []string{"https://issuer.example"},
		TokenEndpoint: endpoint,
		DefaultTarget: &oas.OAuth2DefaultTarget{Audience: "https://api.internal", Scopes: []string{"read"}},
	}
	if cacheEnabled {
		p.Cache = &oas.OAuth2ExchangeCache{Enabled: true}
	}
	return p
}

func exchangeState(p oas.OAuth2TokenExchangeProvider) *oauth2common.State {
	return &oauth2common.State{
		Claims: jwt.MapClaims{
			oas.OAuth2ClaimIss: "https://issuer.example",
			oas.OAuth2ClaimAzp: "agent-app",
		},
		RawToken: "inbound-token",
		OASConfig: &oas.OAuth2{
			TokenExchange: &oas.OAuth2TokenExchange{Enabled: true, Providers: []oas.OAuth2TokenExchangeProvider{p}},
		},
		APIID: "api-1",
	}
}

func newMiddleware(base BaseMiddleware, cache oauth2common.ExchangeCache) *Middleware {
	spec := model.MergedAPI{
		APIDefinition: &apidef.APIDefinition{},
		OAS:           &oas.OAS{},
	}
	spec.APIDefinition.Proxy.ListenPath = "/api/"
	return NewMiddleware(base, spec, cache)
}

// processInTrace drives ProcessRequest with the request already inside a trace,
// returning the inbound trace id and the ended spans.
func processInTrace(t *testing.T, m *Middleware, st *oauth2common.State, sr *tracetest.SpanRecorder) string {
	t.Helper()
	ctx, parent := otel.Tracer("test").Start(context.Background(), "request")
	r := httptest.NewRequest(http.MethodPost, "http://gw/api/tools", nil).WithContext(ctx)
	oauth2common.SetState(r, st)

	_, _ = m.ProcessRequest(httptest.NewRecorder(), r, nil)
	parent.End()
	return parent.SpanContext().TraceID().String()
}

func findSpan(spans []sdktrace.ReadOnlySpan, name string) sdktrace.ReadOnlySpan {
	for _, s := range spans {
		if s.Name() == name {
			return s
		}
	}
	return nil
}

func spanAttr(s sdktrace.ReadOnlySpan, key string) (string, bool) {
	for _, kv := range s.Attributes() {
		if string(kv.Key) == key {
			return kv.Value.AsString(), true
		}
	}
	return "", false
}

// --- tests ---

// TestProcessRequest_SuccessSpanMetricAudit pins TC2, TC7, TC10, TC11, TC15:
// a cache-miss success opens a child oauth2.exchange span that joins the
// request's trace, nests the IdP client span under it, records the requests
// metric with an IdP-touching duration, and fires the Succeeded audit event —
// with only bounded values on the span.
func TestProcessRequest_SuccessSpanMetricAudit(t *testing.T) {
	sr := installRecorder(t)
	idp := okIdP(t, 60*time.Millisecond, "downstream-app")
	t.Cleanup(idp.Close)

	base := newFakeBase()
	m := newMiddleware(base, nil)
	traceID := processInTrace(t, m, exchangeState(provider("corpIdP", idp.URL, false)), sr)

	spans := sr.Ended()
	exch := findSpan(spans, exchangeSpanName)
	require.NotNil(t, exch, "oauth2.exchange span must be opened")

	// TC10: the span joined the request's trace, not a new one.
	assert.Equal(t, traceID, exch.SpanContext().TraceID().String())

	// TC11: a child IdP client span nests under the exchange span.
	idpSpan := findSpan(spans, "oauth2.idp POST")
	require.NotNil(t, idpSpan, "cache miss must emit a child IdP client span")
	assert.Equal(t, exch.SpanContext().SpanID(), idpSpan.Parent().SpanID())

	// TC15: only bounded provider/outcome/cache_status attributes; no identity.
	gotProvider, _ := spanAttr(exch, spanAttrProvider)
	gotOutcome, _ := spanAttr(exch, spanAttrOutcome)
	gotCache, _ := spanAttr(exch, spanAttrCacheStatus)
	assert.Equal(t, "corpIdP", gotProvider)
	assert.Equal(t, "ok", gotOutcome)
	assert.Equal(t, cacheStatusMiss, gotCache)
	for _, kv := range exch.Attributes() {
		assert.Contains(t, []string{spanAttrProvider, spanAttrOutcome, spanAttrCacheStatus}, string(kv.Key))
	}

	// TC2: one requests metric with a real (IdP) duration.
	require.Len(t, base.metrics, 1)
	assert.Equal(t, "ok", base.metrics[0].outcome)
	assert.Equal(t, "corpIdP", base.metrics[0].provider)
	assert.Greater(t, base.metrics[0].duration, time.Duration(0))
	assert.Empty(t, base.cacheHits)

	// TC7: one Succeeded audit event with the safe meta and no identity.
	require.Len(t, base.events, 1)
	assert.Equal(t, apidef.TykEvent(event.OAuth2ExchangeSucceeded), base.events[0].name)
	meta := base.events[0].meta
	assert.Equal(t, "ok", meta["oauth2_exchange_outcome"])
	assert.Equal(t, "agent-app", meta["oauth2_subject_azp"])
	assert.Equal(t, "downstream-app", meta["oauth2_exchanged_azp"])
	assert.NotContains(t, meta, "oauth2_subject_jti")
	assert.NotContains(t, meta, "sub")
}

// TestProcessRequest_IdPErrorEmitsFailed pins TC3/TC8: an IdP rejection records
// the idp_error metric and fires the Failed audit event with the IdP code.
func TestProcessRequest_IdPErrorEmitsFailed(t *testing.T) {
	sr := installRecorder(t)
	idp := erroringIdP()
	t.Cleanup(idp.Close)

	base := newFakeBase()
	m := newMiddleware(base, nil)
	processInTrace(t, m, exchangeState(provider("corpIdP", idp.URL, false)), sr)

	require.Len(t, base.metrics, 1)
	assert.Equal(t, "idp_error", base.metrics[0].outcome)

	require.Len(t, base.events, 1)
	assert.Equal(t, apidef.TykEvent(event.OAuth2ExchangeFailed), base.events[0].name)
	assert.Equal(t, "idp_error", base.events[0].meta["oauth2_exchange_outcome"])
	assert.Equal(t, "invalid_grant", base.events[0].meta["oauth2_idp_error"])

	exch := findSpan(sr.Ended(), exchangeSpanName)
	require.NotNil(t, exch)
	gotOutcome, _ := spanAttr(exch, spanAttrOutcome)
	assert.Equal(t, "idp_error", gotOutcome)
}

// TestProcessRequest_NoMatchingProvider pins TC4: a token from an unconfigured
// issuer records the no_matching_provider metric and audits as Failed.
func TestProcessRequest_NoMatchingProvider(t *testing.T) {
	sr := installRecorder(t)
	idp := okIdP(t, 0, "x")
	t.Cleanup(idp.Close)

	base := newFakeBase()
	m := newMiddleware(base, nil)
	st := exchangeState(provider("corpIdP", idp.URL, false))
	st.Claims[oas.OAuth2ClaimIss] = "https://unconfigured.example"
	processInTrace(t, m, st, sr)

	require.Len(t, base.metrics, 1)
	assert.Equal(t, "no_matching_provider", base.metrics[0].outcome)

	require.Len(t, base.events, 1)
	assert.Equal(t, apidef.TykEvent(event.OAuth2ExchangeFailed), base.events[0].name)
	assert.Equal(t, "no_matching_provider", base.events[0].meta["oauth2_exchange_outcome"])
}

// TestProcessRequest_CacheHitOmitsIdPSpan pins TC9/TC12: a warm second request
// is served from cache — no child IdP span, cache_status=hit, the dedicated
// cache_hit counter increments, and it still audits as a success.
func TestProcessRequest_CacheHitOmitsIdPSpan(t *testing.T) {
	idp := okIdP(t, 0, "downstream-app")
	t.Cleanup(idp.Close)

	base := newFakeBase()
	m := newMiddleware(base, &fakeCache{items: map[string]string{}})
	p := provider("corpIdP", idp.URL, true)

	// Warm the cache (miss), then a second identical request (hit).
	sr1 := installRecorder(t)
	processInTrace(t, m, exchangeState(p), sr1)
	require.NotNil(t, findSpan(sr1.Ended(), "oauth2.idp POST"), "first request is a miss")

	sr2 := installRecorder(t)
	processInTrace(t, m, exchangeState(p), sr2)

	// No IdP round-trip on the hit.
	assert.Nil(t, findSpan(sr2.Ended(), "oauth2.idp POST"), "cache hit must not call the IdP")
	exch := findSpan(sr2.Ended(), exchangeSpanName)
	require.NotNil(t, exch)
	gotCache, _ := spanAttr(exch, spanAttrCacheStatus)
	assert.Equal(t, cacheStatusHit, gotCache)

	// The hit incremented the dedicated cache_hit counter and audited success.
	require.Len(t, base.cacheHits, 1)
	assert.Equal(t, "corpIdP", base.cacheHits[0])
	last := base.metrics[len(base.metrics)-1]
	assert.Equal(t, "ok", last.outcome)
	lastEvent := base.events[len(base.events)-1]
	assert.Equal(t, apidef.TykEvent(event.OAuth2ExchangeSucceeded), lastEvent.name)
	assert.Equal(t, true, lastEvent.meta["oauth2_exchange_cache_hit"])
}

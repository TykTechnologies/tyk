//go:build ee || dev

package oauth2tokenexchange

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/internal/oauth2common"
)

// forbiddenIdentityKeys are the PII / token-id fields the no-hashing model
// drops outright (never hashed, never emitted) from logs and audit meta.
var forbiddenIdentityKeys = []string{
	"oauth2_subject_jti",
	"oauth2_subject_sub",
	"oauth2_act_sub",
	"oauth2_act",
	"sub",
	"jti",
}

func okPayload() EventPayload {
	return EventPayload{
		TraceID:         "0af7651916cd43dd8448eb211c80319c",
		APIID:           "api-1",
		Provider:        "corpIdP",
		Outcome:         oauth2common.OutcomeOK,
		CacheHit:        false,
		DurationMS:      80,
		SubjectAzp:      "agent-app",
		ExchangedAzp:    "downstream-app",
		Audience:        "https://api.internal",
		ScopesRequested: []string{"read", "write"},
	}
}

// TestEventPayload_LogFields_SafeFields pins TC6: the structured log line
// carries the safe fields and none of the dropped identity / token fields.
func TestEventPayload_LogFields_SafeFields(t *testing.T) {
	t.Parallel()

	f := okPayload().LogFields()

	assert.Equal(t, "0af7651916cd43dd8448eb211c80319c", f["trace_id"])
	assert.Equal(t, "api-1", f["oauth2_api_id"])
	assert.Equal(t, "corpIdP", f["oauth2_provider"])
	assert.Equal(t, "ok", f["oauth2_exchange_outcome"])
	assert.Equal(t, false, f["oauth2_exchange_cache_hit"])
	assert.Equal(t, int64(80), f["duration_ms"])
	assert.Equal(t, "agent-app", f["oauth2_subject_azp"])
	assert.Equal(t, "downstream-app", f["oauth2_exchanged_azp"])
	assert.Equal(t, "https://api.internal", f["oauth2_audience"])
	assert.Equal(t, []string{"read", "write"}, f["oauth2_scopes_requested"])

	assertNoForbiddenKeys(t, f)
}

// TestEventPayload_LogFields_FailureCarriesIdPError pins TC6's failure variant.
func TestEventPayload_LogFields_FailureCarriesIdPError(t *testing.T) {
	t.Parallel()

	p := okPayload()
	p.Outcome = oauth2common.OutcomeIdPError
	p.IdpError = "invalid_grant"
	p.IdpErrorDesc = "subject token expired"

	f := p.LogFields()
	assert.Equal(t, "idp_error", f["oauth2_exchange_outcome"])
	assert.Equal(t, "invalid_grant", f["oauth2_idp_error"])
	assert.Equal(t, "subject token expired", f["oauth2_idp_error_description"])
	assertNoForbiddenKeys(t, f)
}

// TestEventPayload_LogFields_OmitsEmptyParty pins that absent party identifiers
// stay absent rather than emitting empty strings.
func TestEventPayload_LogFields_OmitsEmptyParty(t *testing.T) {
	t.Parallel()

	p := okPayload()
	p.ExchangedAzp = ""
	p.TraceID = ""

	f := p.LogFields()
	assert.NotContains(t, f, "oauth2_exchanged_azp")
	assert.NotContains(t, f, "trace_id")
	assert.Contains(t, f, "oauth2_subject_azp")
}

// TestEventPayload_LogFields_CapsIdPErrorDescription pins that an oversized IdP
// error description is length-capped before it reaches the log line.
func TestEventPayload_LogFields_CapsIdPErrorDescription(t *testing.T) {
	t.Parallel()

	p := okPayload()
	p.Outcome = oauth2common.OutcomeIdPError
	p.IdpError = "server_error"
	p.IdpErrorDesc = strings.Repeat("x", oauth2common.MaxIdPErrorBodyBytes+500)

	desc, _ := p.LogFields()["oauth2_idp_error_description"].(string)
	assert.LessOrEqual(t, len(desc), oauth2common.MaxIdPErrorBodyBytes+len("...(truncated)"))
}

// TestEventPayload_AuditMeta_Succeeded pins TC7: a successful exchange's audit
// meta carries the oauth2_-namespaced safe fields and no identity/token.
func TestEventPayload_AuditMeta_Succeeded(t *testing.T) {
	t.Parallel()

	meta := okPayload().AuditMeta()

	assert.Equal(t, "api-1", meta["oauth2_api_id"])
	assert.Equal(t, "corpIdP", meta["oauth2_provider"])
	assert.Equal(t, "ok", meta["oauth2_exchange_outcome"])
	assert.Equal(t, "https://api.internal", meta["oauth2_audience"])
	assert.Equal(t, []string{"read", "write"}, meta["oauth2_scopes_requested"])
	assert.Equal(t, "agent-app", meta["oauth2_subject_azp"])
	assert.Equal(t, "downstream-app", meta["oauth2_exchanged_azp"])
	assert.Equal(t, false, meta["oauth2_exchange_cache_hit"])

	// duration_ms is a log-only field; it must not ride on the audit meta.
	assert.NotContains(t, meta, "duration_ms")

	assertNoForbiddenKeys(t, meta)
}

// TestEventPayload_AuditMeta_FailedCarriesIdPError pins TC8.
func TestEventPayload_AuditMeta_FailedCarriesIdPError(t *testing.T) {
	t.Parallel()

	p := okPayload()
	p.Outcome = oauth2common.OutcomeIdPError
	p.IdpError = "invalid_grant"

	meta := p.AuditMeta()
	assert.Equal(t, "idp_error", meta["oauth2_exchange_outcome"])
	assert.Equal(t, "invalid_grant", meta["oauth2_idp_error"])
	assertNoForbiddenKeys(t, meta)
}

// TestEventPayload_AuditDecision pins TC7/TC8/TC14: ok → Succeeded; idp_error
// and no_matching_provider → Failed; misconfig → no audit event.
func TestEventPayload_AuditDecision(t *testing.T) {
	t.Parallel()

	tests := []struct {
		outcome   oauth2common.OutcomeKind
		wantEvent event.Event
		wantAudit bool
	}{
		{oauth2common.OutcomeOK, event.OAuth2ExchangeSucceeded, true},
		{oauth2common.OutcomeIdPError, event.OAuth2ExchangeFailed, true},
		{oauth2common.OutcomeNoMatchingProvider, event.OAuth2ExchangeFailed, true},
		{oauth2common.OutcomeMisconfig, "", false},
	}
	for _, tt := range tests {
		t.Run(string(tt.outcome), func(t *testing.T) {
			t.Parallel()
			p := okPayload()
			p.Outcome = tt.outcome
			ev, audit := p.AuditDecision()
			assert.Equal(t, tt.wantAudit, audit)
			if tt.wantAudit {
				assert.Equal(t, tt.wantEvent, ev)
			}
		})
	}
}

// TestEventPayload_CacheHitFieldFlows pins TC9: a cache-hit success carries
// oauth2_exchange_cache_hit=true on both the log line and the audit meta, and still
// audits as a success.
func TestEventPayload_CacheHitFieldFlows(t *testing.T) {
	t.Parallel()

	p := okPayload()
	p.CacheHit = true

	assert.Equal(t, true, p.LogFields()["oauth2_exchange_cache_hit"])
	assert.Equal(t, true, p.AuditMeta()["oauth2_exchange_cache_hit"])
	ev, audit := p.AuditDecision()
	assert.True(t, audit)
	assert.Equal(t, event.OAuth2ExchangeSucceeded, ev)
}

// TestEventPayload_NoRawTokenAnywhere pins that neither transform leaks the
// raw inbound or exchanged token (the payload has no token field at all).
func TestEventPayload_NoRawTokenAnywhere(t *testing.T) {
	t.Parallel()

	p := okPayload()
	p.Outcome = oauth2common.OutcomeIdPError
	p.IdpError = "invalid_grant"
	p.IdpErrorDesc = "token rejected"

	for _, m := range []map[string]interface{}{p.LogFields(), p.AuditMeta()} {
		for k, v := range m {
			s := strings.ToLower(fmt.Sprintf("%s=%v", k, v))
			assert.NotContains(t, s, "bearer ")
			assert.NotContains(t, s, "eyj") // base64url JWT header prefix
		}
	}
}

func assertNoForbiddenKeys(t *testing.T, m map[string]interface{}) {
	t.Helper()
	for _, k := range forbiddenIdentityKeys {
		assert.NotContains(t, m, k, "field %q must never be emitted (no-hashing identity model)", k)
	}
}

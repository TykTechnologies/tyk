package oas

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
)

// MCPProxy is the OAS extension that lives on the MCP Proxy APIDef under
// `x-tyk-api-gateway.server.mcpProxy`. Its presence marks the APIDef as the
// public face of an MCP feature (see RFC §7).
//
// Tag convention follows existing siblings on XTykAPIGateway.Server:
// camelCase for both json and bson, with acronym suffixes treated as plain
// words (e.g., `apiId`, `url`).
type MCPProxy struct {
	// ProtocolVersion advertised in the initialize handshake.
	ProtocolVersion string `bson:"protocolVersion" json:"protocolVersion"`

	// Sources is the ordered list of source bindings. Order is alphabetical
	// by SourceSlug, deterministic for tools/list output.
	Sources []MCPSource `bson:"sources" json:"sources"`
}

// MCPSource binds a single source (loopback APIDef or upstream HTTPS) into
// the MCP Proxy's tool surface (see RFC §7).
type MCPSource struct {
	// SourceSlug — stable, sanitised slug used as the namespace prefix in
	// tool names. Derived from the source API id (loopback) or info.title
	// (upstream raw OAS) at create-time. Immutable after create.
	SourceSlug string `bson:"sourceSlug" json:"sourceSlug"`

	// BackendMode ∈ {"loopback", "upstream"}.
	BackendMode string `bson:"backendMode" json:"backendMode"`

	// SourceAPIID — required for BackendMode=="loopback"; empty for "upstream".
	SourceAPIID string `bson:"sourceApiId,omitempty" json:"sourceApiId,omitempty"`

	// UpstreamURL — fully-resolved absolute URL for BackendMode=="upstream".
	// Derived from source OAS servers[0].url with UpstreamServerVars
	// substituted at create-time. Must contain no remaining "{"/"}".
	UpstreamURL        string            `bson:"upstreamUrl,omitempty" json:"upstreamUrl,omitempty"`
	UpstreamServerVars map[string]string `bson:"upstreamServerVars,omitempty" json:"upstreamServerVars,omitempty"`

	// UpstreamOAS — raw OAS 3.1 document for BackendMode=="upstream". The
	// derive pass at proxy load (see apidef/oas/mcp_proxy_derive.go) reads
	// operations from here because there is no source APIDef to read from.
	// Nil for BackendMode=="loopback".
	UpstreamOAS json.RawMessage `bson:"upstreamOas,omitempty" json:"upstreamOas,omitempty"`

	// UpstreamCred — outbound static credential for BackendMode=="upstream".
	// Nil for keyless upstreams or BackendMode=="loopback".
	UpstreamCred *UpstreamCred `bson:"upstreamCred,omitempty" json:"upstreamCred,omitempty"`

	// ServiceCred — GA-only field (service-credential injection). Persisted
	// for forward compatibility; rejected at write-time in the PoC.
	ServiceCred *ServiceCredRef `bson:"serviceCred,omitempty" json:"serviceCred,omitempty"`
}

// MCPToolMapping is the runtime-only descriptor for a derived MCP tool. It is
// NOT persisted: no json/bson tags, never marshalled into stored APIDef
// documents. Built at proxy load by DeriveSourceTools (see
// mcp_proxy_derive.go) and consumed by the request-phase MCPHandler.
type MCPToolMapping struct {
	ToolName       string
	SourceSlug     string
	Method         string
	PathTemplate   string
	OperationID    string
	Description    string
	InputSchema    json.RawMessage
	OutputSchema   json.RawMessage
	ParamLocations map[string]string
}

// UpstreamCred is the outbound static credential applied by mode-(b)
// upstream sources (see RFC §7).
type UpstreamCred struct {
	// AuthType ∈ {"none","header","bearer"}. PoC accepts these only;
	// mtls is GA.
	AuthType   string `bson:"authType" json:"authType"`
	HeaderName string `bson:"headerName,omitempty" json:"headerName,omitempty"`
	// SecretValue — inline static secret. PoC accepts inline only;
	// SecretRef (vault://, k8s-secret://, tyk-store://) is GA.
	SecretValue string `bson:"secretValue,omitempty" json:"secretValue,omitempty"`
}

// ServiceCredRef is a GA-only service-credential reference. Persisted for
// forward compatibility but rejected at write-time in the PoC.
type ServiceCredRef struct {
	AuthType  string          `bson:"authType" json:"authType"` // "apikey"|"jwt"|"oauth2_cc"|"mtls"|"keyless"
	SecretRef string          `bson:"secretRef" json:"secretRef"`
	OAuth2    *OAuth2CCConfig `bson:"oauth2,omitempty" json:"oauth2,omitempty"`
}

// OAuth2CCConfig is the OAuth 2.0 client-credentials configuration for
// GA-time service credentials.
type OAuth2CCConfig struct {
	TokenURL          string   `bson:"tokenUrl" json:"tokenUrl"`
	Scopes            []string `bson:"scopes,omitempty" json:"scopes,omitempty"`
	DefaultTTLSeconds int      `bson:"defaultTtlSeconds,omitempty" json:"defaultTtlSeconds,omitempty"`
}

// Fill is a no-op: the MCPProxy extension has no peer in apidef.APIDefinition;
// the data lives only on the OAS side and round-trips via JSON marshalling.
// The method exists to match the Fill/ExtractTo convention of every other
// sibling on Server.
func (m *MCPProxy) Fill(_ apidef.APIDefinition) {}

// ExtractTo is a no-op for the same reason as Fill.
func (m *MCPProxy) ExtractTo(_ *apidef.APIDefinition) {}

// MCPProxyValidationError aggregates structural validation violations on an
// MCPProxy spec. Each entry in Codes is a stable error class so callers can
// pattern-match without parsing strings (see RFC §12.2).
type MCPProxyValidationError struct {
	Codes   []string
	Details []string
}

// Error implements error.
func (e *MCPProxyValidationError) Error() string {
	if e == nil || len(e.Codes) == 0 {
		return "mcp proxy validation: ok"
	}
	if len(e.Details) > 0 {
		return fmt.Sprintf("mcp proxy validation failed: codes=%s details=%s",
			strings.Join(e.Codes, ","), strings.Join(e.Details, "; "))
	}
	return fmt.Sprintf("mcp proxy validation failed: codes=%s", strings.Join(e.Codes, ","))
}

// HasCode reports whether the error contains the given error code.
func (e *MCPProxyValidationError) HasCode(code string) bool {
	if e == nil {
		return false
	}
	for _, c := range e.Codes {
		if c == code {
			return true
		}
	}
	return false
}

// Error code constants exposed for callers that want to pattern-match
// without string-typing.
const (
	MCPErrNotImplementedInPoC               = "not_implemented_in_poc"
	MCPErrUpstreamURLContainsPlaceholder    = "upstream_url_contains_placeholder"
	MCPErrLoopbackSourceMissingAPIID        = "loopback_source_missing_source_api_id"
	MCPErrUpstreamSourceMissingOAS          = "upstream_source_missing_oas"
	MCPErrDuplicateSourceSlug               = "duplicate_source_slug"
	MCPNotImplementedDetailServiceCred      = "service_cred"
	MCPNotImplementedDetailUpstreamCredMTLS = "upstream_cred_mtls"
)

// Validate runs the structural (no-runtime-state) subset of the MCP Proxy
// admission rules from RFC §12.2. Runtime-state checks (source_not_loaded,
// loopback_source_requires_mcp_caller_auth_or_keyless,
// mtls_loopback_source_unsupported_in_poc) live in gateway/ (Phase C).
//
// Multiple violations are accumulated, not short-circuited.
func (m *MCPProxy) Validate(_ context.Context) error {
	if m == nil {
		return nil
	}

	verr := &MCPProxyValidationError{}

	// not_implemented_in_poc bucket — single error class, multiple details.
	notImplDetails := map[string]struct{}{}

	seenSlugs := map[string]struct{}{}

	for i := range m.Sources {
		src := &m.Sources[i]

		if src.ServiceCred != nil {
			notImplDetails[MCPNotImplementedDetailServiceCred] = struct{}{}
		}

		if src.UpstreamCred != nil && src.UpstreamCred.AuthType == "mtls" {
			notImplDetails[MCPNotImplementedDetailUpstreamCredMTLS] = struct{}{}
		}

		if src.BackendMode == "upstream" {
			if strings.ContainsAny(src.UpstreamURL, "{}") {
				verr.Codes = append(verr.Codes, MCPErrUpstreamURLContainsPlaceholder)
				verr.Details = append(verr.Details,
					fmt.Sprintf("sources[%d].upstreamUrl contains unresolved placeholder", i))
			}
			if len(src.UpstreamOAS) == 0 {
				verr.Codes = append(verr.Codes, MCPErrUpstreamSourceMissingOAS)
				verr.Details = append(verr.Details,
					fmt.Sprintf("sources[%d].upstreamOas required for backendMode=upstream", i))
			}
		}

		if src.BackendMode == "loopback" && src.SourceAPIID == "" {
			verr.Codes = append(verr.Codes, MCPErrLoopbackSourceMissingAPIID)
			verr.Details = append(verr.Details,
				fmt.Sprintf("sources[%d].sourceApiId required for backendMode=loopback", i))
		}

		if src.SourceSlug != "" {
			if _, dup := seenSlugs[src.SourceSlug]; dup {
				verr.Codes = append(verr.Codes, MCPErrDuplicateSourceSlug)
				verr.Details = append(verr.Details,
					fmt.Sprintf("sources[%d].sourceSlug %q duplicates an earlier source", i, src.SourceSlug))
			} else {
				seenSlugs[src.SourceSlug] = struct{}{}
			}
		}
	}

	if len(notImplDetails) > 0 {
		verr.Codes = append(verr.Codes, MCPErrNotImplementedInPoC)
		// Stable detail order so error strings are deterministic for tests.
		if _, ok := notImplDetails[MCPNotImplementedDetailServiceCred]; ok {
			verr.Details = append(verr.Details, MCPNotImplementedDetailServiceCred)
		}
		if _, ok := notImplDetails[MCPNotImplementedDetailUpstreamCredMTLS]; ok {
			verr.Details = append(verr.Details, MCPNotImplementedDetailUpstreamCredMTLS)
		}
	}

	if len(verr.Codes) == 0 {
		return nil
	}
	return verr
}

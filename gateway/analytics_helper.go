package gateway

import (
	"bytes"
	"encoding/base64"
	"net/http"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/httputil"
	"github.com/TykTechnologies/tyk/user"
)

func getRawRequest(r *http.Request, spec *APISpec) string {
	var wireFormatReq bytes.Buffer

	var originalHeaders http.Header
	if !spec.GlobalConfig.AnalyticsConfig.AllowUnsafeDetailedLogs {
		originalHeaders = obfuscateAuthorizationHeaders(r, spec)
	}

	r.Write(&wireFormatReq)
	rawRequest := base64.StdEncoding.EncodeToString(wireFormatReq.Bytes())

	if originalHeaders != nil {
		r.Header = originalHeaders
	}

	return rawRequest
}

func obfuscateAuthorizationHeaders(r *http.Request, spec *APISpec) http.Header {
	original := r.Header.Clone()
	authNames := make([]string, 0)

	addAuthHeader := func(config apidef.AuthConfig) {
		if config.DisableHeader {
			return
		}

		name := config.AuthHeaderName
		if name == "" {
			name = header.Authorization
		}
		authNames = append(authNames, http.CanonicalHeaderKey(name))
	}

	addAuthHeader(spec.Auth)

	for _, authConfig := range spec.AuthConfigs {
		addAuthHeader(authConfig)
	}

	for _, authName := range authNames {
		if _, ok := r.Header[authName]; ok {
			r.Header.Set(authName, obfuscationToken)
		}
	}

	return original
}

func recordDetail(r *http.Request, spec *APISpec) bool {
	// when streaming in grpc, we do not record the request
	if httputil.IsStreamingRequest(r) {
		return false
	}

	return recordDetailUnsafe(r, spec)
}

func recordDetailUnsafe(r *http.Request, spec *APISpec) bool {
	if spec.EnableDetailedRecording {
		return true
	}

	if session := ctxGetSession(r); session != nil {
		if session.EnableDetailedRecording || session.EnableDetailRecording { // nolint:staticcheck // Deprecated DetailRecording
			return true
		}
	}

	// decide based on org session.
	if spec.GlobalConfig.EnforceOrgDataDetailLogging {
		session, ok := r.Context().Value(ctx.OrgSessionContext).(*user.SessionState)
		if ok && session != nil {
			return session.EnableDetailedRecording || session.EnableDetailRecording // nolint:staticcheck // Deprecated DetailRecording
		}
	}

	// no org session found, use global config
	return spec.GraphQL.Enabled || spec.GlobalConfig.AnalyticsConfig.EnableDetailedRecording
}

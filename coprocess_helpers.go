// +build coprocess

package main

import (
	"github.com/TykTechnologies/tyk/coprocess"
)

// TykSessionState takes a coprocess.SessionState (as returned by the Protocol Buffer binding), and outputs a standard Tyk SessionState.
func TykSessionState(sessionState *coprocess.SessionState) SessionState {
	var session SessionState

	accessDefinitions := make(map[string]AccessDefinition, len(sessionState.AccessRights))

	for key, protoAccessDefinition := range sessionState.AccessRights {
		allowedUrls := make([]AccessSpec, len(protoAccessDefinition.AllowedUrls))
		for _, protoAllowedURL := range protoAccessDefinition.AllowedUrls {
			allowedURL := AccessSpec{protoAllowedURL.Url, protoAllowedURL.Methods}
			allowedUrls = append(allowedUrls, allowedURL)
		}
		accessDefinition := AccessDefinition{protoAccessDefinition.ApiName, protoAccessDefinition.ApiId, protoAccessDefinition.Versions, allowedUrls}
		accessDefinitions[key] = accessDefinition
	}

	var basicAuthData struct {
		Password string   `json:"password" msg:"password"`
		Hash     HashType `json:"hash_type" msg:"hash_type"`
	}
	if sessionState.BasicAuthData != nil {
		basicAuthData.Password = sessionState.BasicAuthData.Password
		basicAuthData.Hash = HashType(sessionState.BasicAuthData.Hash)
	}

	var jwtData struct {
		Secret string `json:"secret" msg:"secret"`
	}
	if sessionState.JwtData != nil {
		jwtData.Secret = sessionState.JwtData.Secret
	}

	var monitor struct {
		TriggerLimits []float64 `json:"trigger_limits" msg:"trigger_limits"`
	}

	if sessionState.Monitor != nil {
		monitor.TriggerLimits = sessionState.Monitor.TriggerLimits
	}

	session = SessionState{
		sessionState.LastCheck,
		sessionState.Allowance,
		sessionState.Rate,
		sessionState.Per,
		sessionState.Expires,
		sessionState.QuotaMax,
		sessionState.QuotaRenews,
		sessionState.QuotaRemaining,
		sessionState.QuotaRenewalRate,
		accessDefinitions,
		sessionState.OrgId,
		sessionState.OauthClientId,
		sessionState.OauthKeys,
		basicAuthData,
		jwtData,
		sessionState.HmacEnabled,
		sessionState.HmacSecret,
		sessionState.IsInactive,
		sessionState.ApplyPolicyId,
		sessionState.DataExpires,
		monitor,
		sessionState.EnableDetailedRecording,
		nil,
		sessionState.Tags,
		sessionState.Alias,
		sessionState.LastUpdated,
		sessionState.IdExtractorDeadline,
		sessionState.SessionLifetime,
		"",
	}

	return session
}

// ProtoSessionState takes a standard SessionState and outputs a SessionState object compatible with Protocol Buffers.
func ProtoSessionState(sessionState SessionState) *coprocess.SessionState {

	accessDefinitions := make(map[string]*coprocess.AccessDefinition, len(sessionState.AccessRights))

	for key, accessDefinition := range sessionState.AccessRights {
		var allowedUrls []*coprocess.AccessSpec
		for _, allowedURL := range accessDefinition.AllowedURLs {
			accessSpec := &coprocess.AccessSpec{allowedURL.URL, allowedURL.Methods}
			allowedUrls = append(allowedUrls, accessSpec)
		}

		protoAccessDefinition := &coprocess.AccessDefinition{
			accessDefinition.APIName, accessDefinition.APIID, accessDefinition.Versions, allowedUrls,
		}

		accessDefinitions[key] = protoAccessDefinition

	}

	var basicAuthData *coprocess.BasicAuthData
	basicAuthData = &coprocess.BasicAuthData{sessionState.BasicAuthData.Password, string(sessionState.BasicAuthData.Hash)}

	var jwtData *coprocess.JWTData
	jwtData = &coprocess.JWTData{sessionState.JWTData.Secret}

	var monitor *coprocess.Monitor
	monitor = &coprocess.Monitor{sessionState.Monitor.TriggerLimits}

	session := &coprocess.SessionState{
		sessionState.LastCheck,
		sessionState.Allowance,
		sessionState.Rate,
		sessionState.Per,
		sessionState.Expires,
		sessionState.QuotaMax,
		sessionState.QuotaRenews,
		sessionState.QuotaRemaining,
		sessionState.QuotaRenewalRate,
		accessDefinitions,
		sessionState.OrgID,
		sessionState.OauthClientID,
		sessionState.OauthKeys,
		basicAuthData,
		jwtData,
		sessionState.HMACEnabled,
		sessionState.HmacSecret,
		sessionState.IsInactive,
		sessionState.ApplyPolicyID,
		sessionState.DataExpires,
		monitor,
		sessionState.EnableDetailedRecording,
		"",
		sessionState.Tags,
		sessionState.Alias,
		sessionState.LastUpdated,
		sessionState.IdExtractorDeadline,
		sessionState.SessionLifetime,
	}

	return session
}

// ProtoMap is a helper function for maps with string slice values.
func ProtoMap(inputMap map[string][]string) map[string]string {
	newMap := make(map[string]string, 0)

	if inputMap != nil {
		for k, v := range inputMap {
			newMap[k] = v[0]
		}
	}

	return newMap
}

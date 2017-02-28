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
			accessSpec := &coprocess.AccessSpec{
				Url:     allowedURL.URL,
				Methods: allowedURL.Methods,
			}
			allowedUrls = append(allowedUrls, accessSpec)
		}

		accessDefinitions[key] = &coprocess.AccessDefinition{
			ApiName:     accessDefinition.APIName,
			ApiId:       accessDefinition.APIID,
			Versions:    accessDefinition.Versions,
			AllowedUrls: allowedUrls,
		}
	}

	basicAuthData := &coprocess.BasicAuthData{
		Password: sessionState.BasicAuthData.Password,
		Hash:     string(sessionState.BasicAuthData.Hash),
	}
	jwtData := &coprocess.JWTData{
		Secret: sessionState.JWTData.Secret,
	}
	monitor := &coprocess.Monitor{
		TriggerLimits: sessionState.Monitor.TriggerLimits,
	}

	session := &coprocess.SessionState{
		LastCheck:               sessionState.LastCheck,
		Allowance:               sessionState.Allowance,
		Rate:                    sessionState.Rate,
		Per:                     sessionState.Per,
		Expires:                 sessionState.Expires,
		QuotaMax:                sessionState.QuotaMax,
		QuotaRenews:             sessionState.QuotaRenews,
		QuotaRemaining:          sessionState.QuotaRemaining,
		QuotaRenewalRate:        sessionState.QuotaRenewalRate,
		AccessRights:            accessDefinitions,
		OrgId:                   sessionState.OrgID,
		OauthClientId:           sessionState.OauthClientID,
		OauthKeys:               sessionState.OauthKeys,
		BasicAuthData:           basicAuthData,
		JwtData:                 jwtData,
		HmacEnabled:             sessionState.HMACEnabled,
		HmacSecret:              sessionState.HmacSecret,
		IsInactive:              sessionState.IsInactive,
		ApplyPolicyId:           sessionState.ApplyPolicyID,
		DataExpires:             sessionState.DataExpires,
		Monitor:                 monitor,
		EnableDetailedRecording: sessionState.EnableDetailedRecording,
		Metadata:                "",
		Tags:                    sessionState.Tags,
		Alias:                   sessionState.Alias,
		LastUpdated:             sessionState.LastUpdated,
		IdExtractorDeadline:     sessionState.IdExtractorDeadline,
		SessionLifetime:         sessionState.SessionLifetime,
	}

	return session
}

// ProtoMap is a helper function for maps with string slice values.
func ProtoMap(inputMap map[string][]string) map[string]string {
	newMap := make(map[string]string)

	if inputMap != nil {
		for k, v := range inputMap {
			newMap[k] = v[0]
		}
	}

	return newMap
}

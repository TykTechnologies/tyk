// +build coprocess

package main

import (
	"github.com/TykTechnologies/tyk/coprocess"
)

// TykSessionState takes a coprocess.SessionState (as returned by the Protocol Buffer binding), and outputs a standard Tyk SessionState.
func TykSessionState(session *coprocess.SessionState) *SessionState {
	accessDefinitions := make(map[string]AccessDefinition, len(session.AccessRights))

	for key, protoAccessDefinition := range session.AccessRights {
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
	if session.BasicAuthData != nil {
		basicAuthData.Password = session.BasicAuthData.Password
		basicAuthData.Hash = HashType(session.BasicAuthData.Hash)
	}

	var jwtData struct {
		Secret string `json:"secret" msg:"secret"`
	}
	if session.JwtData != nil {
		jwtData.Secret = session.JwtData.Secret
	}

	var monitor struct {
		TriggerLimits []float64 `json:"trigger_limits" msg:"trigger_limits"`
	}

	if session.Monitor != nil {
		monitor.TriggerLimits = session.Monitor.TriggerLimits
	}

	return &SessionState{
		session.LastCheck,
		session.Allowance,
		session.Rate,
		session.Per,
		session.Expires,
		session.QuotaMax,
		session.QuotaRenews,
		session.QuotaRemaining,
		session.QuotaRenewalRate,
		accessDefinitions,
		session.OrgId,
		session.OauthClientId,
		session.OauthKeys,
		basicAuthData,
		jwtData,
		session.HmacEnabled,
		session.HmacSecret,
		session.IsInactive,
		session.ApplyPolicyId,
		session.ApplyPolicies,
		session.DataExpires,
		monitor,
		session.EnableDetailedRecording,
		nil,
		session.Tags,
		session.Alias,
		session.LastUpdated,
		session.IdExtractorDeadline,
		session.SessionLifetime,
		"",
	}
}

// ProtoSessionState takes a standard SessionState and outputs a SessionState object compatible with Protocol Buffers.
func ProtoSessionState(session *SessionState) *coprocess.SessionState {

	accessDefinitions := make(map[string]*coprocess.AccessDefinition, len(session.AccessRights))

	for key, accessDefinition := range session.AccessRights {
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
		Password: session.BasicAuthData.Password,
		Hash:     string(session.BasicAuthData.Hash),
	}
	jwtData := &coprocess.JWTData{
		Secret: session.JWTData.Secret,
	}
	monitor := &coprocess.Monitor{
		TriggerLimits: session.Monitor.TriggerLimits,
	}

	return &coprocess.SessionState{
		LastCheck:               session.LastCheck,
		Allowance:               session.Allowance,
		Rate:                    session.Rate,
		Per:                     session.Per,
		Expires:                 session.Expires,
		QuotaMax:                session.QuotaMax,
		QuotaRenews:             session.QuotaRenews,
		QuotaRemaining:          session.QuotaRemaining,
		QuotaRenewalRate:        session.QuotaRenewalRate,
		AccessRights:            accessDefinitions,
		OrgId:                   session.OrgID,
		OauthClientId:           session.OauthClientID,
		OauthKeys:               session.OauthKeys,
		BasicAuthData:           basicAuthData,
		JwtData:                 jwtData,
		HmacEnabled:             session.HMACEnabled,
		HmacSecret:              session.HmacSecret,
		IsInactive:              session.IsInactive,
		ApplyPolicyId:           session.ApplyPolicyID,
		ApplyPolicies:           session.ApplyPolicies,
		DataExpires:             session.DataExpires,
		Monitor:                 monitor,
		EnableDetailedRecording: session.EnableDetailedRecording,
		Tags:                session.Tags,
		Alias:               session.Alias,
		LastUpdated:         session.LastUpdated,
		IdExtractorDeadline: session.IdExtractorDeadline,
		SessionLifetime:     session.SessionLifetime,
	}
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

package gateway

import (
	"encoding/json"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/coprocess"
	"github.com/TykTechnologies/tyk/user"
)

// TykSessionState takes a coprocess.SessionState (as returned by the Protocol Buffer binding), and outputs a standard Tyk SessionState.
func TykSessionState(session *coprocess.SessionState) *user.SessionState {
	accessDefinitions := make(map[string]user.AccessDefinition, len(session.AccessRights))

	for key, protoAccDef := range session.AccessRights {
		allowedUrls := make([]user.AccessSpec, len(protoAccDef.AllowedUrls))
		for _, protoAllowedURL := range protoAccDef.AllowedUrls {
			allowedUrls = append(allowedUrls, user.AccessSpec{
				URL:     protoAllowedURL.Url,
				Methods: protoAllowedURL.Methods,
			})
		}
		accessDefinitions[key] = user.AccessDefinition{
			APIName:     protoAccDef.ApiName,
			APIID:       protoAccDef.ApiId,
			Versions:    protoAccDef.Versions,
			AllowedURLs: allowedUrls,
		}
	}

	var basicAuthData user.BasicAuthData
	if session.BasicAuthData != nil {
		basicAuthData.Password = session.BasicAuthData.Password
		basicAuthData.Hash = user.HashType(session.BasicAuthData.Hash)
	}

	var jwtData user.JWTData
	if session.JwtData != nil {
		jwtData.Secret = session.JwtData.Secret
	}

	var monitor user.Monitor
	if session.Monitor != nil {
		monitor.TriggerLimits = session.Monitor.TriggerLimits
	}

	metadata := make(map[string]interface{})
	if session.Metadata != nil {
		for k, v := range session.Metadata {
			metadata[k] = v
		}
	}

	return &user.SessionState{
		LastCheck:               session.LastCheck,
		Allowance:               session.Allowance,
		Rate:                    session.Rate,
		Per:                     session.Per,
		MaxQueryDepth:           int(session.MaxQueryDepth),
		Expires:                 session.Expires,
		QuotaMax:                session.QuotaMax,
		QuotaRenews:             session.QuotaRenews,
		QuotaRemaining:          session.QuotaRemaining,
		QuotaRenewalRate:        session.QuotaRenewalRate,
		AccessRights:            accessDefinitions,
		OrgID:                   session.OrgId,
		OauthClientID:           session.OauthClientId,
		OauthKeys:               session.OauthKeys,
		Certificate:             session.Certificate,
		BasicAuthData:           basicAuthData,
		JWTData:                 jwtData,
		HMACEnabled:             session.HmacEnabled,
		HmacSecret:              session.HmacSecret,
		IsInactive:              session.IsInactive,
		ApplyPolicyID:           session.ApplyPolicyId,
		ApplyPolicies:           session.ApplyPolicies,
		DataExpires:             session.DataExpires,
		MetaData:                metadata,
		Monitor:                 monitor,
		EnableDetailedRecording: session.EnableDetailedRecording,
		Tags:                    session.Tags,
		Alias:                   session.Alias,
		LastUpdated:             session.LastUpdated,
		IdExtractorDeadline:     session.IdExtractorDeadline,
		SessionLifetime:         session.SessionLifetime,
		PostExpiryAction:        user.PostExpiryAction(session.PostExpiryAction),
		PostExpiryGracePeriod:   session.PostExpiryGracePeriod,
		KeyID:                   session.KeyId,
	}
}

// ProtoSessionState takes a standard SessionState and outputs a SessionState object compatible with Protocol Buffers.
func ProtoSessionState(session *user.SessionState) *coprocess.SessionState {

	var accessDefinitions map[string]*coprocess.AccessDefinition
	if len(session.AccessRights) > 0 {
		accessDefinitions = make(map[string]*coprocess.AccessDefinition, len(session.AccessRights))
		for key, accessDefinition := range session.AccessRights {
			allowedUrls := make([]*coprocess.AccessSpec, 0, len(accessDefinition.AllowedURLs))
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
	}

	var basicAuthData *coprocess.BasicAuthData
	if session.BasicAuthData.Password != "" || len(session.BasicAuthData.Hash) > 0 {
		basicAuthData = &coprocess.BasicAuthData{
			Password: session.BasicAuthData.Password,
			Hash:     string(session.BasicAuthData.Hash),
		}
	}

	var jwtData *coprocess.JWTData
	if session.JWTData.Secret != "" {
		jwtData = &coprocess.JWTData{
			Secret: session.JWTData.Secret,
		}
	}

	var monitor *coprocess.Monitor
	if len(session.Monitor.TriggerLimits) > 0 {
		monitor = &coprocess.Monitor{
			TriggerLimits: session.Monitor.TriggerLimits,
		}
	}

	var metadata map[string]string
	if len(session.MetaData) > 0 {
		metadata = make(map[string]string, len(session.MetaData))
		for k, v := range session.MetaData {
			switch v.(type) {
			case string:
				metadata[k] = v.(string)
			default:
				jsonValue, err := json.Marshal(v)
				if err != nil {
					log.WithFields(logrus.Fields{
						"prefix": "coprocess",
					}).WithError(err).Error("Couldn't encode session metadata")
					continue
				}
				metadata[k] = string(jsonValue)
			}
		}
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
		Metadata:                metadata,
		EnableDetailedRecording: session.EnableDetailRecording || session.EnableDetailedRecording,
		Tags:                    session.Tags,
		Alias:                   session.Alias,
		LastUpdated:             session.LastUpdated,
		IdExtractorDeadline:     session.IdExtractorDeadline,
		SessionLifetime:         session.SessionLifetime,
		PostExpiryAction:        string(session.PostExpiryAction),
		PostExpiryGracePeriod:   session.PostExpiryGracePeriod,
		KeyId:                   session.KeyID,
	}
}

// ProtoMap is a helper function for maps with string slice values.
func ProtoMap(inputMap map[string][]string) map[string]string {
	if len(inputMap) == 0 {
		return nil
	}
	newMap := make(map[string]string, len(inputMap))
	for k, v := range inputMap {
		if len(v) > 0 {
			newMap[k] = v[0]
		}
	}
	return newMap
}

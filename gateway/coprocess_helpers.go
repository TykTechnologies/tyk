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

	var basicAuthData struct {
		Password string        `json:"password" msg:"password"`
		Hash     user.HashType `json:"hash_type" msg:"hash_type"`
	}
	if session.GetBasicAuthData() != nil {
		basicAuthData.Password = session.GetBasicAuthData().Password
		basicAuthData.Hash = user.HashType(session.GetBasicAuthData().Hash)
	}

	var jwtData struct {
		Secret string `json:"secret" msg:"secret"`
	}
	if session.GetJwtData() != nil {
		jwtData.Secret = session.JwtData.Secret
	}

	var monitor struct {
		TriggerLimits []float64 `json:"trigger_limits" msg:"trigger_limits"`
	}

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
		LastCheck:               session.GetLastCheck(),
		Allowance:               session.GetAllowance(),
		Rate:                    session.GetRate(),
		Per:                     session.GetPer(),
		MaxQueryDepth:           int(session.GetMaxQueryDepth()),
		Expires:                 session.GetExpires(),
		QuotaMax:                session.GetQuotaMax(),
		QuotaRenews:             session.GetQuotaRenews(),
		QuotaRemaining:          session.GetQuotaRemaining(),
		QuotaRenewalRate:        session.GetQuotaRenewalRate(),
		AccessRights:            accessDefinitions,
		OrgID:                   session.GetOrgId(),
		OauthClientID:           session.GetOauthClientId(),
		OauthKeys:               session.GetOauthKeys(),
		Certificate:             session.GetCertificate(),
		BasicAuthData:           basicAuthData,
		JWTData:                 jwtData,
		HMACEnabled:             session.GetHmacEnabled(),
		HmacSecret:              session.GetHmacSecret(),
		IsInactive:              session.GetIsInactive(),
		ApplyPolicyID:           session.GetApplyPolicyId(),
		ApplyPolicies:           session.GetApplyPolicies(),
		DataExpires:             session.GetDataExpires(),
		MetaData:                metadata,
		Monitor:                 monitor,
		EnableDetailedRecording: session.GetEnableDetailedRecording(),
		Tags:                    session.GetTags(),
		Alias:                   session.GetAlias(),
		LastUpdated:             session.GetLastUpdated(),
		IdExtractorDeadline:     session.GetIdExtractorDeadline(),
		SessionLifetime:         session.GetSessionLifetime(),
	}
}

// ProtoSessionState takes a standard SessionState and outputs a SessionState object compatible with Protocol Buffers.
func ProtoSessionState(session *user.SessionState) *coprocess.SessionState {

	accessDefinitions := make(map[string]*coprocess.AccessDefinition, len(session.GetAccessRights()))

	for key, accessDefinition := range session.GetAccessRights() {
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
		Password: session.GetBasicAuthData().Password,
		Hash:     string(session.GetBasicAuthData().Hash),
	}
	jwtData := &coprocess.JWTData{
		Secret: session.GetJWTData().Secret,
	}
	monitor := &coprocess.Monitor{
		TriggerLimits: session.GetMonitor().TriggerLimits,
	}

	metadata := make(map[string]string)
	if len(session.GetMetaData()) > 0 {
		for k, v := range session.GetMetaData() {
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
		LastCheck:               session.GetLastCheck(),
		Allowance:               session.GetAllowance(),
		Rate:                    session.GetRate(),
		Per:                     session.GetPer(),
		Expires:                 session.GetExpires(),
		QuotaMax:                session.GetQuotaMax(),
		QuotaRenews:             session.GetQuotaRenews(),
		QuotaRemaining:          session.GetQuotaRemaining(),
		QuotaRenewalRate:        session.GetQuotaRenewalRate(),
		AccessRights:            accessDefinitions,
		OrgId:                   session.GetOrgID(),
		OauthClientId:           session.GetOauthClientID(),
		OauthKeys:               session.GetOauthKeys(),
		BasicAuthData:           basicAuthData,
		JwtData:                 jwtData,
		HmacEnabled:             session.GetHMACEnabled(),
		HmacSecret:              session.GetHmacSecret(),
		IsInactive:              session.GetIsInactive(),
		ApplyPolicyId:           session.GetApplyPolicyID(),
		ApplyPolicies:           session.GetApplyPolicies(),
		DataExpires:             session.GetDataExpires(),
		Monitor:                 monitor,
		Metadata:                metadata,
		EnableDetailedRecording: session.GetEnableDetailRecording() || session.GetEnableDetailedRecording(),
		Tags:                    session.GetTags(),
		Alias:                   session.GetAlias(),
		LastUpdated:             session.GetLastUpdated(),
		IdExtractorDeadline:     session.GetIdExtractorDeadline(),
		SessionLifetime:         session.GetSessionLifetime(),
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

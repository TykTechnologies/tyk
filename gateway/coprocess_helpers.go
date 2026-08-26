package gateway

import (
	"encoding/json"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/coprocess"
	"github.com/TykTechnologies/tyk/user"
)

// TykSessionState takes a coprocess.SessionState (as returned by the Protocol Buffer binding), and outputs a standard Tyk SessionState.
func TykSessionState(session *coprocess.SessionState) *user.SessionState {
	accessDefinitions := make(map[string]user.AccessDefinition, len(session.AccessRights))

	for key, protoAccDef := range session.AccessRights {
		// Note the capacity, not the length: allocating by length and then
		// appending left every access definition padded with as many
		// zero-valued specs as it had real ones. A spec with an empty URL is
		// an empty regex, which matches every path, so those padding entries
		// granted a custom-auth session access to the whole API.
		allowedUrls := make([]user.AccessSpec, 0, len(protoAccDef.AllowedUrls))
		for _, protoAllowedURL := range protoAccDef.AllowedUrls {
			allowedUrls = append(allowedUrls, user.AccessSpec{
				URL:        protoAllowedURL.Url,
				Methods:    protoAllowedURL.Methods,
				Conditions: tykAccessConditions(protoAllowedURL.Conditions),
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

	accessDefinitions := make(map[string]*coprocess.AccessDefinition, len(session.AccessRights))

	for key, accessDefinition := range session.AccessRights {
		var allowedUrls []*coprocess.AccessSpec
		for _, allowedURL := range accessDefinition.AllowedURLs {
			accessSpec := &coprocess.AccessSpec{
				Url:        allowedURL.URL,
				Methods:    allowedURL.Methods,
				Conditions: protoAccessConditions(allowedURL.Conditions),
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

	metadata := make(map[string]string)
	if len(session.MetaData) > 0 {
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
	newMap := make(map[string]string)

	if inputMap != nil {
		for k, v := range inputMap {
			newMap[k] = v[0]
		}
	}

	return newMap
}

// Granular access conditions have to survive the round trip through a
// coprocess plugin in both directions. Dropping one does not merely lose
// configuration: a condition is the only thing narrowing the URL it hangs off,
// so a session that comes back without it grants strictly more than the one
// that went out.

// tykAccessConditions converts the Protocol Buffer representation of a spec's
// conditions to the Gateway's own.
func tykAccessConditions(protoConditions []*coprocess.AccessCondition) []user.AccessCondition {
	if len(protoConditions) == 0 {
		return nil
	}

	conditions := make([]user.AccessCondition, 0, len(protoConditions))
	for _, protoCondition := range protoConditions {
		if protoCondition == nil {
			continue
		}

		conditions = append(conditions, user.AccessCondition{
			On:      apidef.RoutingTriggerOnType(protoCondition.On),
			Options: tykTriggerOptions(protoCondition.Options),
		})
	}

	return conditions
}

func tykTriggerOptions(protoOptions *coprocess.RoutingTriggerOptions) apidef.RoutingTriggerOptions {
	if protoOptions == nil {
		return apidef.RoutingTriggerOptions{}
	}

	return apidef.RoutingTriggerOptions{
		HeaderMatches:         tykStringRegexMaps(protoOptions.HeaderMatches),
		QueryValMatches:       tykStringRegexMaps(protoOptions.QueryValMatches),
		PathPartMatches:       tykStringRegexMaps(protoOptions.PathPartMatches),
		SessionMetaMatches:    tykStringRegexMaps(protoOptions.SessionMetaMatches),
		RequestContextMatches: tykStringRegexMaps(protoOptions.RequestContextMatches),
		PayloadMatches:        tykStringRegexMap(protoOptions.PayloadMatches),
	}
}

func tykStringRegexMaps(in map[string]*coprocess.StringRegexMap) map[string]apidef.StringRegexMap {
	if len(in) == 0 {
		return nil
	}

	out := make(map[string]apidef.StringRegexMap, len(in))
	for name, value := range in {
		out[name] = tykStringRegexMap(value)
	}

	return out
}

func tykStringRegexMap(in *coprocess.StringRegexMap) apidef.StringRegexMap {
	if in == nil {
		return apidef.StringRegexMap{}
	}

	return apidef.StringRegexMap{
		MatchPattern: in.MatchRx,
		Reverse:      in.Reverse,
	}
}

// protoAccessConditions converts a spec's conditions to their Protocol Buffer
// representation.
func protoAccessConditions(conditions []user.AccessCondition) []*coprocess.AccessCondition {
	if len(conditions) == 0 {
		return nil
	}

	protoConditions := make([]*coprocess.AccessCondition, 0, len(conditions))
	for _, condition := range conditions {
		protoConditions = append(protoConditions, &coprocess.AccessCondition{
			On:      string(condition.On),
			Options: protoTriggerOptions(condition.Options),
		})
	}

	return protoConditions
}

func protoTriggerOptions(options apidef.RoutingTriggerOptions) *coprocess.RoutingTriggerOptions {
	return &coprocess.RoutingTriggerOptions{
		HeaderMatches:         protoStringRegexMaps(options.HeaderMatches),
		QueryValMatches:       protoStringRegexMaps(options.QueryValMatches),
		PathPartMatches:       protoStringRegexMaps(options.PathPartMatches),
		SessionMetaMatches:    protoStringRegexMaps(options.SessionMetaMatches),
		RequestContextMatches: protoStringRegexMaps(options.RequestContextMatches),
		PayloadMatches:        protoStringRegexMap(options.PayloadMatches),
	}
}

func protoStringRegexMaps(in map[string]apidef.StringRegexMap) map[string]*coprocess.StringRegexMap {
	if len(in) == 0 {
		return nil
	}

	out := make(map[string]*coprocess.StringRegexMap, len(in))
	for name, value := range in {
		out[name] = protoStringRegexMap(value)
	}

	return out
}

func protoStringRegexMap(in apidef.StringRegexMap) *coprocess.StringRegexMap {
	return &coprocess.StringRegexMap{
		MatchRx: in.MatchPattern,
		Reverse: in.Reverse,
	}
}

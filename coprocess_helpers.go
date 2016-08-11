// +build coprocess

package main

import(
  "github.com/TykTechnologies/tyk/coprocess"
)

func TykSessionState(sessionState *coprocess.SessionState) SessionState {
  var session SessionState

  basicAuthData := struct{
    Password string   `json:"password" msg:"password"`
    Hash     HashType `json:"hash_type" msg:"hash_type"`
  }{"", HASH_PlainText}

  jwtData := struct{
    Secret string `json:"secret" msg:"secret"`
  }{""}

  monitor := struct{
    TriggerLimits []float64 `json:"trigger_limits" msg:"trigger_limits"`
  }{[]float64{}}

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
    map[string]AccessDefinition{},
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
  }
  return session
}

func ProtoSessionState(sessionState SessionState) *coprocess.SessionState {

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
    nil, // AccessRights map[string]*AccessDefinition
    sessionState.OrgID,
    sessionState.OauthClientID,
    sessionState.OauthKeys,
    nil, // BasicAuthData *SessionState_BasicAuthData
    nil, // JwtData *SessionState_JWTData
    sessionState.HMACEnabled,
    sessionState.HmacSecret,
    sessionState.IsInactive,
    sessionState.ApplyPolicyID,
    sessionState.DataExpires,
    nil, // Monitor *SessionState_Monitor
    sessionState.EnableDetailedRecording,
    "",
    sessionState.Tags,
    sessionState.Alias,
  }

  return session
}

func ProtoMap(inputMap map[string][]string) map[string]string {
	newMap := make(map[string]string, 0)

	if inputMap != nil {
		for k, v := range inputMap {
			newMap[k] = v[0]
		}
	}

	return newMap
}

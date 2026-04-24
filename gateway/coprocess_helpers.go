package gateway

import (
	"encoding/json"
	"sync"

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
var (
	coprocessObjectPool = sync.Pool{
		New: func() interface{} {
			return &coprocess.Object{}
		},
	}
	coprocessSessionStatePool = sync.Pool{
		New: func() interface{} {
			return &coprocess.SessionState{}
		},
	}
	coprocessMiniRequestObjectPool = sync.Pool{
		New: func() interface{} {
			return &coprocess.MiniRequestObject{}
		},
	}
	coprocessResponseObjectPool = sync.Pool{
		New: func() interface{} {
			return &coprocess.ResponseObject{}
		},
	}
	coprocessAccessDefinitionPool = sync.Pool{
		New: func() interface{} {
			return &coprocess.AccessDefinition{}
		},
	}
	coprocessBasicAuthDataPool = sync.Pool{
		New: func() interface{} {
			return &coprocess.BasicAuthData{}
		},
	}
	coprocessJWTDataPool = sync.Pool{
		New: func() interface{} {
			return &coprocess.JWTData{}
		},
	}
	coprocessMonitorPool = sync.Pool{
		New: func() interface{} {
			return &coprocess.Monitor{}
		},
	}
	coprocessAccessSpecPool = sync.Pool{
		New: func() interface{} {
			return &coprocess.AccessSpec{}
		},
	}
)

func ReleaseCoprocessObject(obj *coprocess.Object) {
	if obj == nil {
		return
	}

	if obj.Request != nil {
		req := obj.Request
		for k := range req.Headers {
			delete(req.Headers, k)
		}
		for k := range req.SetHeaders {
			delete(req.SetHeaders, k)
		}
		req.DeleteHeaders = req.DeleteHeaders[:0]
		for k := range req.Params {
			delete(req.Params, k)
		}
		for k := range req.AddParams {
			delete(req.AddParams, k)
		}
		for k := range req.ExtendedParams {
			delete(req.ExtendedParams, k)
		}
		req.DeleteParams = req.DeleteParams[:0]
		req.Url = ""
		req.Method = ""
		req.RequestUri = ""
		req.Scheme = ""
		req.Body = ""
		req.RawBody = req.RawBody[:0]
		if req.ReturnOverrides != nil {
			req.ReturnOverrides.ResponseCode = 0
			req.ReturnOverrides.ResponseError = ""
			req.ReturnOverrides.Headers = nil
			req.ReturnOverrides.OverrideError = false
			req.ReturnOverrides.ResponseBody = ""
		}
		coprocessMiniRequestObjectPool.Put(req)
		obj.Request = nil
	}

	if obj.Response != nil {
		res := obj.Response
		for k := range res.Headers {
			delete(res.Headers, k)
		}
		res.MultivalueHeaders = res.MultivalueHeaders[:0]
		res.StatusCode = 0
		res.Body = ""
		res.RawBody = res.RawBody[:0]
		coprocessResponseObjectPool.Put(res)
		obj.Response = nil
	}

	if obj.Session != nil {
		sess := obj.Session
		for k, v := range sess.AccessRights {
			if v != nil {
				for _, u := range v.AllowedUrls {
					if u != nil {
						u.Url = ""
						u.Methods = u.Methods[:0]
						coprocessAccessSpecPool.Put(u)
					}
				}
				v.AllowedUrls = v.AllowedUrls[:0]
				v.ApiName = ""
				v.ApiId = ""
				v.Versions = v.Versions[:0]
				coprocessAccessDefinitionPool.Put(v)
			}
			delete(sess.AccessRights, k)
		}
		for k := range sess.Metadata {
			delete(sess.Metadata, k)
		}
		if sess.BasicAuthData != nil {
			sess.BasicAuthData.Password = ""
			sess.BasicAuthData.Hash = ""
			coprocessBasicAuthDataPool.Put(sess.BasicAuthData)
			sess.BasicAuthData = nil
		}
		if sess.JwtData != nil {
			sess.JwtData.Secret = ""
			coprocessJWTDataPool.Put(sess.JwtData)
			sess.JwtData = nil
		}
		if sess.Monitor != nil {
			sess.Monitor.TriggerLimits = sess.Monitor.TriggerLimits[:0]
			coprocessMonitorPool.Put(sess.Monitor)
			sess.Monitor = nil
		}
		for k := range sess.OauthKeys {
			delete(sess.OauthKeys, k)
		}
		sess.ApplyPolicies = sess.ApplyPolicies[:0]
		sess.Tags = sess.Tags[:0]
		coprocessSessionStatePool.Put(sess)
		obj.Session = nil
	}

	for k := range obj.Metadata {
		delete(obj.Metadata, k)
	}
	for k := range obj.Spec {
		delete(obj.Spec, k)
	}
	obj.HookName = ""
	obj.HookType = 0
	
	coprocessObjectPool.Put(obj)
}

func ProtoSessionState(session *user.SessionState) *coprocess.SessionState {

	accessDefinitions := make(map[string]*coprocess.AccessDefinition, len(session.AccessRights))

	for key, accessDefinition := range session.AccessRights {
		var allowedUrls []*coprocess.AccessSpec
		for _, allowedURL := range accessDefinition.AllowedURLs {
			accessSpec := coprocessAccessSpecPool.Get().(*coprocess.AccessSpec)
			accessSpec.Url = allowedURL.URL
			accessSpec.Methods = allowedURL.Methods
			allowedUrls = append(allowedUrls, accessSpec)
		}

		ad := coprocessAccessDefinitionPool.Get().(*coprocess.AccessDefinition)
		ad.ApiName = accessDefinition.APIName
		ad.ApiId = accessDefinition.APIID
		ad.Versions = accessDefinition.Versions
		ad.AllowedUrls = allowedUrls
		accessDefinitions[key] = ad
	}

	basicAuthData := coprocessBasicAuthDataPool.Get().(*coprocess.BasicAuthData)
	basicAuthData.Password = session.BasicAuthData.Password
	basicAuthData.Hash = string(session.BasicAuthData.Hash)

	jwtData := coprocessJWTDataPool.Get().(*coprocess.JWTData)
	jwtData.Secret = session.JWTData.Secret

	monitor := coprocessMonitorPool.Get().(*coprocess.Monitor)
	monitor.TriggerLimits = session.Monitor.TriggerLimits

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

	sess := coprocessSessionStatePool.Get().(*coprocess.SessionState)
	sess.LastCheck = session.LastCheck
	sess.Allowance = session.Allowance
	sess.Rate = session.Rate
	sess.Per = session.Per
	sess.Expires = session.Expires
	sess.QuotaMax = session.QuotaMax
	sess.QuotaRenews = session.QuotaRenews
	sess.QuotaRemaining = session.QuotaRemaining
	sess.QuotaRenewalRate = session.QuotaRenewalRate
	sess.AccessRights = accessDefinitions
	sess.OrgId = session.OrgID
	sess.OauthClientId = session.OauthClientID
	sess.OauthKeys = session.OauthKeys
	sess.BasicAuthData = basicAuthData
	sess.JwtData = jwtData
	sess.HmacEnabled = session.HMACEnabled
	sess.HmacSecret = session.HmacSecret
	sess.IsInactive = session.IsInactive
	sess.ApplyPolicyId = session.ApplyPolicyID
	sess.ApplyPolicies = session.ApplyPolicies
	sess.DataExpires = session.DataExpires
	sess.Monitor = monitor
	sess.Metadata = metadata
	sess.EnableDetailedRecording = session.EnableDetailRecording || session.EnableDetailedRecording
	sess.Tags = session.Tags
	sess.Alias = session.Alias
	sess.LastUpdated = session.LastUpdated
	sess.IdExtractorDeadline = session.IdExtractorDeadline
	sess.SessionLifetime = session.SessionLifetime
	sess.PostExpiryAction = string(session.PostExpiryAction)
	sess.PostExpiryGracePeriod = session.PostExpiryGracePeriod
	sess.KeyId = session.KeyID

	return sess
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

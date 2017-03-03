package main

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
	"github.com/pmylund/go-cache"

	"github.com/TykTechnologies/logrus"
	"github.com/TykTechnologies/tyk/apidef"
)

type JWTMiddleware struct {
	*TykMiddleware
}

func (k *JWTMiddleware) GetName() string {
	return "JWTMiddleware"
}

var JWKCache *cache.Cache

type JWK struct {
	Alg string   `json:"alg"`
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	X5c []string `json:"x5c"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	KID string   `json:"kid"`
	X5t string   `json:"x5t"`
}

type JWKs struct {
	Keys []JWK `json:"keys"`
}

func (k JWTMiddleware) New() {}

// GetConfig retrieves the configuration from the API config
func (k *JWTMiddleware) GetConfig() (interface{}, error) {
	return k.TykMiddleware.Spec.APIDefinition.Auth, nil
}

func (k *JWTMiddleware) IsEnabledForSpec() bool { return true }

func (k *JWTMiddleware) getSecretFromURL(url, kid, keyType string) ([]byte, error) {
	// Implement a cache
	if JWKCache == nil {
		log.Debug("Creating JWK Cache")
		JWKCache = cache.New(240*time.Second, 30*time.Second)
	}

	var jwkSet JWKs
	cachedJWK, found := JWKCache.Get(k.TykMiddleware.Spec.APIID)
	if !found {
		// Get the JWK
		log.Debug("Pulling JWK")
		response, err := http.Get(url)
		if err != nil {
			log.Error("Failed to get resource URL: ", err)
			return nil, err
		}

		// Decode it
		defer response.Body.Close()
		contents, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Error("Failed to read body data: ", err)
			return nil, err
		}

		if err := json.Unmarshal(contents, &jwkSet); err != nil {
			log.Error("Failed to decode body JWK: ", err)
			return nil, err
		}

		// Cache it
		log.Debug("Caching JWK")
		JWKCache.Set(k.TykMiddleware.Spec.APIID, jwkSet, cache.DefaultExpiration)
	} else {
		jwkSet = cachedJWK.(JWKs)
	}

	log.Debug("Checking JWKs...")
	for _, val := range jwkSet.Keys {
		if val.KID != kid || strings.ToLower(val.Kty) != strings.ToLower(keyType) {
			continue
		}
		if len(val.X5c) > 0 {
			// Use the first cert only
			decodedCert, err := base64.StdEncoding.DecodeString(val.X5c[0])
			if err != nil {
				return nil, err
			}
			log.Debug("Found cert! Replying...")
			log.Debug("Cert was: ", string(decodedCert))
			return decodedCert, nil
		}
		return nil, errors.New("no certificates in JWK")
	}

	return nil, errors.New("No matching KID could be found")
}

func (k *JWTMiddleware) getIdentityFomToken(token *jwt.Token) (string, bool) {
	// Try using a kid or sub header
	idFound := false
	var tykId string
	if token.Header["kid"] != nil {
		tykId = token.Header["kid"].(string)
		idFound = true
	}

	if !idFound {
		if token.Claims.(jwt.MapClaims)["sub"] != nil {
			tykId = token.Claims.(jwt.MapClaims)["sub"].(string)
			idFound = true
		}
	}

	log.Debug("Found: ", tykId)
	return tykId, idFound
}

func (k *JWTMiddleware) getSecret(token *jwt.Token) ([]byte, error) {
	config := k.TykMiddleware.Spec.APIDefinition
	// Check for central JWT source
	if config.JWTSource != "" {

		// Is it a URL?
		if httpScheme.MatchString(config.JWTSource) {
			secret, err := k.getSecretFromURL(config.JWTSource, token.Header["kid"].(string), k.TykMiddleware.Spec.JWTSigningMethod)
			if err != nil {
				return nil, err
			}

			return secret, nil
		}

		// If not, return the actual value
		decodedCert, err := base64.StdEncoding.DecodeString(config.JWTSource)
		if err != nil {
			return nil, err
		}
		return decodedCert, nil
	}

	// Try using a kid or sub header
	tykId, found := k.getIdentityFomToken(token)

	if !found {
		return nil, errors.New("Key ID not found")
	}

	// Couldn't base64 decode the kid, so lets try it raw
	log.Debug("Getting key: ", tykId)
	sessionState, rawKeyExists := k.TykMiddleware.CheckSessionAndIdentityForValidKey(tykId)
	if !rawKeyExists {
		log.Info("Not found!")
		return nil, errors.New("token invalid, key not found")
	}
	return []byte(sessionState.JWTData.Secret), nil
}

func (k *JWTMiddleware) getBasePolicyID(token *jwt.Token) (string, bool) {
	if k.TykMiddleware.Spec.APIDefinition.JWTPolicyFieldName != "" {
		basePolicyID, foundPolicy := token.Claims.(jwt.MapClaims)[k.TykMiddleware.Spec.APIDefinition.JWTPolicyFieldName].(string)
		if !foundPolicy {
			log.Error("Could not identify a policy to apply to this token from field!")
			return "", false
		}

		return basePolicyID, true

	} else if k.TykMiddleware.Spec.APIDefinition.JWTClientIDBaseField != "" {
		clientID, clientIDFound := token.Claims.(jwt.MapClaims)[k.TykMiddleware.Spec.APIDefinition.JWTClientIDBaseField].(string)
		if !clientIDFound {
			log.Error("Could not identify a policy to apply to this token from field!")
			return "", false
		}

		// Check for a regular token that matches this client ID
		clientsessionState, exists := k.TykMiddleware.CheckSessionAndIdentityForValidKey(clientID)
		if !exists {
			return "", false
		}

		if clientsessionState.ApplyPolicyID == "" {
			return "", false
		}

		// Use the policy from the client ID
		return clientsessionState.ApplyPolicyID, true
	}

	return "", false
}

// processCentralisedJWT Will check a JWT token centrally against the secret stored in the API Definition.
func (k *JWTMiddleware) processCentralisedJWT(w http.ResponseWriter, r *http.Request, token *jwt.Token) (error, int) {
	log.Debug("JWT authority is centralised")
	// Generate a virtual token
	baseFieldData, baseFound := token.Claims.(jwt.MapClaims)[k.TykMiddleware.Spec.APIDefinition.JWTIdentityBaseField].(string)
	if !baseFound {
		log.Warning("Base Field not found, using SUB")
		var found bool
		baseFieldData, found = token.Claims.(jwt.MapClaims)["sub"].(string)
		if !found {
			log.Error("ID Could not be generated. Failing Request.")
			k.reportLoginFailure("[NOT FOUND]", r)
			return errors.New("Key not authorized"), 403
		}

	}
	log.Debug("Base Field ID set to: ", baseFieldData)
	data := []byte(baseFieldData)
	tokenID := fmt.Sprintf("%x", md5.Sum(data))
	sessionID := k.TykMiddleware.Spec.OrgID + tokenID

	log.Debug("JWT Temporary session ID is: ", sessionID)

	sessionState, exists := k.TykMiddleware.CheckSessionAndIdentityForValidKey(sessionID)
	if !exists {
		// Create it
		log.Debug("Key does not exist, creating")
		sessionState = SessionState{}

		// We need a base policy as a template, either get it from the token itself OR a proxy client ID within Tyk
		basePolicyID, foundPolicy := k.getBasePolicyID(token)
		if !foundPolicy {
			return errors.New("Key not authorized: no matching policy found"), 403
		}

		newSessionState, err := generateSessionFromPolicy(basePolicyID,
			k.TykMiddleware.Spec.APIDefinition.OrgID,
			true)

		if err == nil {
			sessionState = newSessionState
			sessionState.MetaData = map[string]interface{}{"TykJWTSessionID": sessionID}
			sessionState.Alias = baseFieldData

			// Update the session in the session manager in case it gets called again
			k.Spec.SessionManager.UpdateSession(sessionID, sessionState, GetLifetime(k.Spec, &sessionState))
			log.Debug("Policy applied to key")

			switch k.TykMiddleware.Spec.BaseIdentityProvidedBy {
			case apidef.JWTClaim, apidef.UnsetAuth:
				context.Set(r, SessionData, sessionState)
				context.Set(r, AuthHeaderValue, sessionID)
			}
			k.setContextVars(r, token)
			return nil, 200
		}

		k.reportLoginFailure(baseFieldData, r)
		log.Error("Could not find a valid policy to apply to this token!")
		return errors.New("Key not authorized: no matching policy"), 403
	}

	log.Debug("Key found")
	switch k.TykMiddleware.Spec.BaseIdentityProvidedBy {
	case apidef.JWTClaim, apidef.UnsetAuth:
		context.Set(r, SessionData, sessionState)
		context.Set(r, AuthHeaderValue, sessionID)
	}
	k.setContextVars(r, token)
	return nil, 200
}

func (k *JWTMiddleware) reportLoginFailure(tykId string, r *http.Request) {
	// Fire Authfailed Event
	AuthFailed(k.TykMiddleware, r, tykId)

	// Report in health check
	ReportHealthCheckValue(k.Spec.Health, KeyFailure, "1")
}

func (k *JWTMiddleware) processOneToOneTokenMap(w http.ResponseWriter, r *http.Request, token *jwt.Token) (error, int) {
	tykId, found := k.getIdentityFomToken(token)

	if !found {
		k.reportLoginFailure(tykId, r)
		return errors.New("Key id not found"), 403
	}

	log.Debug("Using raw key ID: ", tykId)
	sessionState, exists := k.TykMiddleware.CheckSessionAndIdentityForValidKey(tykId)
	if !exists {
		k.reportLoginFailure(tykId, r)
		return errors.New("Key not authorized"), 403
	}

	log.Debug("Raw key ID found.")
	context.Set(r, SessionData, sessionState)
	context.Set(r, AuthHeaderValue, tykId)
	k.setContextVars(r, token)
	return nil, 200
}

func (k *JWTMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	config := k.TykMiddleware.Spec.APIDefinition.Auth
	var tykId string

	// Get the token
	rawJWT := r.Header.Get(config.AuthHeaderName)
	if config.UseParam {
		tempRes := CopyRequest(r)

		// Set hte header name
		rawJWT = tempRes.FormValue(config.AuthHeaderName)
	}

	if config.UseCookie {
		tempRes := CopyRequest(r)
		authCookie, err := tempRes.Cookie(config.AuthHeaderName)
		if err != nil {
			rawJWT = ""
		} else {
			rawJWT = authCookie.Value
		}
	}

	if rawJWT == "" {
		// No header value, fail
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": GetIPFromRequest(r),
		}).Info("Attempted access with malformed header, no JWT auth header found.")

		log.Debug("Looked in: ", config.AuthHeaderName)
		log.Debug("Raw data was: ", rawJWT)
		log.Debug("Headers are: ", r.Header)

		k.reportLoginFailure(tykId, r)
		return errors.New("Authorization field missing"), 400
	}

	// enable bearer token format
	rawJWT = stripBearer(rawJWT)

	// Verify the token
	token, err := jwt.Parse(rawJWT, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		switch k.TykMiddleware.Spec.JWTSigningMethod {
		case "hmac":
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
		case "rsa":
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
		case "ecdsa":
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
		default:
			log.Warning("No signing method found in API Definition, defaulting to HMAC")
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
		}

		val, err := k.getSecret(token)
		if err != nil {
			log.Error("Couldn't get token: ", err)
		}

		if k.TykMiddleware.Spec.JWTSigningMethod == "rsa" {
			asRSA, err := jwt.ParseRSAPublicKeyFromPEM(val)
			if err != nil {
				log.Error("Failed to deccode JWT to RSA type")
				return nil, err
			}
			return asRSA, err
		}

		return val, err
	})

	if err == nil && token.Valid {
		// Token is valid - let's move on

		// Are we mapping to a central JWT Secret?
		if k.TykMiddleware.Spec.APIDefinition.JWTSource != "" {
			return k.processCentralisedJWT(w, r, token)
		}

		// No, let's try one-to-one mapping
		return k.processOneToOneTokenMap(w, r, token)
	}
	log.WithFields(logrus.Fields{
		"path":   r.URL.Path,
		"origin": GetIPFromRequest(r),
	}).Info("Attempted JWT access with non-existent key.")

	if err != nil {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": GetIPFromRequest(r),
		}).Error("JWT validation error: ", err)
	}

	k.reportLoginFailure(tykId, r)
	return errors.New("Key not authorized"), 403
}

func (k *JWTMiddleware) setContextVars(r *http.Request, token *jwt.Token) {
	// Flatten claims and add to context
	if !k.Spec.EnableContextVars {
		return
	}
	cnt, contextFound := context.GetOk(r, ContextData)
	if contextFound {
		contextDataObject := cnt.(map[string]interface{})
		claimPrefix := "jwt_claims_"

		for claimName, claimValue := range token.Claims.(jwt.MapClaims) {
			claim := claimPrefix + claimName
			contextDataObject[claim] = claimValue
		}

		// Key data
		authHeaderValue := context.Get(r, AuthHeaderValue)
		contextDataObject["token"] = authHeaderValue

		context.Set(r, ContextData, contextDataObject)
	}
}

func generateSessionFromPolicy(policyID, orgID string, enforceOrg bool) (SessionState, error) {
	policy, ok := Policies[policyID]
	sessionState := SessionState{}
	if !ok {
		return sessionState, errors.New("Policy not found")
	}
	// Check ownership, policy org owner must be the same as API,
	// otherwise youcould overwrite a session key with a policy from a different org!

	if enforceOrg {
		if policy.OrgID != orgID {
			log.Error("Attempting to apply policy from different organisation to key, skipping")
			return sessionState, errors.New("Key not authorized: no matching policy")
		}
	} else {
		// Org isn;t enforced, so lets use the policy baseline
		orgID = policy.OrgID
	}

	sessionState.ApplyPolicyID = policyID
	sessionState.OrgID = orgID
	sessionState.Allowance = policy.Rate // This is a legacy thing, merely to make sure output is consistent. Needs to be purged
	sessionState.Rate = policy.Rate
	sessionState.Per = policy.Per
	sessionState.QuotaMax = policy.QuotaMax
	sessionState.QuotaRenewalRate = policy.QuotaRenewalRate
	sessionState.AccessRights = policy.AccessRights
	sessionState.HMACEnabled = policy.HMACEnabled
	sessionState.IsInactive = policy.IsInactive
	sessionState.Tags = policy.Tags

	if policy.KeyExpiresIn > 0 {
		sessionState.Expires = time.Now().Unix() + policy.KeyExpiresIn
	}

	return sessionState, nil
}

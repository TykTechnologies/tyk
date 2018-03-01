package main

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	cache "github.com/pmylund/go-cache"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"
)

type JWTMiddleware struct {
	BaseMiddleware
}

func (k *JWTMiddleware) Name() string {
	return "JWTMiddleware"
}

func (k *JWTMiddleware) EnabledForSpec() bool {
	return k.Spec.EnableJWT
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

func (k *JWTMiddleware) getSecretFromURL(url, kid, keyType string) ([]byte, error) {
	// Implement a cache
	if JWKCache == nil {
		log.Debug("Creating JWK Cache")
		JWKCache = cache.New(240*time.Second, 30*time.Second)
	}

	var jwkSet JWKs
	cachedJWK, found := JWKCache.Get(k.Spec.APIID)
	if !found {
		// Get the JWK
		log.Debug("Pulling JWK")
		resp, err := http.Get(url)
		if err != nil {
			log.Error("Failed to get resource URL: ", err)
			return nil, err
		}
		defer resp.Body.Close()

		// Decode it
		if err := json.NewDecoder(resp.Body).Decode(&jwkSet); err != nil {
			log.Error("Failed to decode body JWK: ", err)
			return nil, err
		}

		// Cache it
		log.Debug("Caching JWK")
		JWKCache.Set(k.Spec.APIID, jwkSet, cache.DefaultExpiration)
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

	if !idFound && token.Claims.(jwt.MapClaims)["sub"] != nil {
		tykId = token.Claims.(jwt.MapClaims)["sub"].(string)
		idFound = true
	}

	log.Debug("Found: ", tykId)
	return tykId, idFound
}

func (k *JWTMiddleware) getSecret(token *jwt.Token) ([]byte, error) {
	config := k.Spec.APIDefinition
	// Check for central JWT source
	if config.JWTSource != "" {
		// Is it a URL?
		if httpScheme.MatchString(config.JWTSource) {
			secret, err := k.getSecretFromURL(config.JWTSource, token.Header["kid"].(string), k.Spec.JWTSigningMethod)
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

		// Is decoded url too?
		if httpScheme.MatchString(string(decodedCert)) {
			secret, err := k.getSecretFromURL(string(decodedCert), token.Header["kid"].(string), k.Spec.JWTSigningMethod)
			if err != nil {
				return nil, err
			}

			return secret, nil
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
	session, rawKeyExists := k.CheckSessionAndIdentityForValidKey(tykId)
	if !rawKeyExists {
		log.Info("Not found!")
		return nil, errors.New("token invalid, key not found")
	}
	return []byte(session.JWTData.Secret), nil
}

func (k *JWTMiddleware) getPolicyIDFromToken(token *jwt.Token) (string, bool) {
	policyID, foundPolicy := token.Claims.(jwt.MapClaims)[k.Spec.JWTPolicyFieldName].(string)
	if !foundPolicy {
		log.Error("Could not identify a policy to apply to this token from field!")
		return "", false
	}

	return policyID, true
}

func (k *JWTMiddleware) getBasePolicyID(token *jwt.Token) (string, bool) {
	if k.Spec.JWTPolicyFieldName != "" {
		return k.getPolicyIDFromToken(token)
	} else if k.Spec.JWTClientIDBaseField != "" {
		clientID, clientIDFound := token.Claims.(jwt.MapClaims)[k.Spec.JWTClientIDBaseField].(string)
		if !clientIDFound {
			log.Error("Could not identify a policy to apply to this token from field!")
			return "", false
		}

		// Check for a regular token that matches this client ID
		clientSession, exists := k.CheckSessionAndIdentityForValidKey(clientID)
		if !exists {
			return "", false
		}

		pols := clientSession.PolicyIDs()
		if len(pols) < 1 {
			return "", false
		}

		// Use the policy from the client ID
		return pols[0], true
	}

	return "", false
}

// processCentralisedJWT Will check a JWT token centrally against the secret stored in the API Definition.
func (k *JWTMiddleware) processCentralisedJWT(r *http.Request, token *jwt.Token) (error, int) {
	log.Debug("JWT authority is centralised")
	// Generate a virtual token
	baseFieldData, baseFound := token.Claims.(jwt.MapClaims)[k.Spec.JWTIdentityBaseField].(string)
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
	sessionID := k.Spec.OrgID + tokenID

	log.Debug("JWT Temporary session ID is: ", sessionID)

	session, exists := k.CheckSessionAndIdentityForValidKey(sessionID)
	if !exists {
		// Create it
		log.Debug("Key does not exist, creating")
		session = user.SessionState{}

		// We need a base policy as a template, either get it from the token itself OR a proxy client ID within Tyk
		basePolicyID, foundPolicy := k.getBasePolicyID(token)
		if !foundPolicy {
			k.reportLoginFailure(baseFieldData, r)
			return errors.New("Key not authorized: no matching policy found"), 403
		}

		newSession, err := generateSessionFromPolicy(basePolicyID,
			k.Spec.OrgID,
			true)
		if err != nil {
			k.reportLoginFailure(baseFieldData, r)
			log.Error("Could not find a valid policy to apply to this token!")
			return errors.New("Key not authorized: no matching policy"), 403
		}

		session = newSession
		session.MetaData = map[string]interface{}{"TykJWTSessionID": sessionID}
		session.Alias = baseFieldData

		// Update the session in the session manager in case it gets called again
		k.Spec.SessionManager.UpdateSession(sessionID, &session, session.Lifetime(k.Spec.SessionLifetime), false)
		log.Debug("Policy applied to key")

		switch k.Spec.BaseIdentityProvidedBy {
		case apidef.JWTClaim, apidef.UnsetAuth:
			ctxSetSession(r, &session)
			ctxSetAuthToken(r, sessionID)
		}
		k.setContextVars(r, token)
		return nil, 200
	} else if k.Spec.JWTPolicyFieldName != "" {
		// extract policy ID from JWT token
		policyID, foundPolicy := k.getPolicyIDFromToken(token)
		if !foundPolicy {
			k.reportLoginFailure(baseFieldData, r)
			return errors.New("Key not authorized: no matching policy found"), 403
		}
		// check if we received a valid policy ID in claim
		policiesMu.RLock()
		policy, ok := policiesByID[policyID]
		policiesMu.RUnlock()
		if !ok {
			k.reportLoginFailure(baseFieldData, r)
			log.Error("Policy ID found in token is invalid!")
			return errors.New("Key not authorized: no matching policy"), 403
		}
		// check if token for this session was switched to another valid policy
		pols := session.PolicyIDs()
		if len(pols) == 0 {
			k.reportLoginFailure(baseFieldData, r)
			log.Error("No policies for the found session. Failing Request.")
			return errors.New("Key not authorized: no matching policy found"), 403
		}
		if pols[0] != policyID { // switch session to new policy and update session storage and cache
			// check ownership before updating session
			if policy.OrgID != k.Spec.OrgID {
				k.reportLoginFailure(baseFieldData, r)
				log.Error("Policy ID found in token is invalid (wrong ownership)!")
				return errors.New("Key not authorized: no matching policy"), 403
			}
			// update session storage
			session.SetPolicies(policyID)
			session.LastUpdated = time.Now().String()
			k.Spec.SessionManager.UpdateSession(sessionID, &session, session.Lifetime(k.Spec.SessionLifetime), false)
			// update session in cache
			go SessionCache.Set(sessionID, session, cache.DefaultExpiration)
		}
	}

	log.Debug("Key found")
	switch k.Spec.BaseIdentityProvidedBy {
	case apidef.JWTClaim, apidef.UnsetAuth:
		ctxSetSession(r, &session)
		ctxSetAuthToken(r, sessionID)
	}
	k.setContextVars(r, token)
	return nil, 200
}

func (k *JWTMiddleware) reportLoginFailure(tykId string, r *http.Request) {
	// Fire Authfailed Event
	AuthFailed(k, r, tykId)

	// Report in health check
	reportHealthValue(k.Spec, KeyFailure, "1")
}

func (k *JWTMiddleware) processOneToOneTokenMap(r *http.Request, token *jwt.Token) (error, int) {
	tykId, found := k.getIdentityFomToken(token)

	if !found {
		k.reportLoginFailure(tykId, r)
		return errors.New("Key id not found"), 404
	}

	log.Debug("Using raw key ID: ", tykId)
	session, exists := k.CheckSessionAndIdentityForValidKey(tykId)
	if !exists {
		k.reportLoginFailure(tykId, r)
		return errors.New("Key not authorized"), 403
	}

	log.Debug("Raw key ID found.")
	ctxSetSession(r, &session)
	ctxSetAuthToken(r, tykId)
	k.setContextVars(r, token)
	return nil, 200
}

func (k *JWTMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	config := k.Spec.Auth
	var tykId string

	// Get the token
	rawJWT := r.Header.Get(config.AuthHeaderName)
	if config.UseParam {
		// Set hte header name
		rawJWT = r.URL.Query().Get(config.AuthHeaderName)
	}

	if config.UseCookie {
		authCookie, err := r.Cookie(config.AuthHeaderName)
		if err != nil {
			rawJWT = ""
		} else {
			rawJWT = authCookie.Value
		}
	}

	if rawJWT == "" {
		// No header value, fail
		logEntry := getLogEntryForRequest(r, "", nil)
		logEntry.Info("Attempted access with malformed header, no JWT auth header found.")

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
		switch k.Spec.JWTSigningMethod {
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
			return nil, err
		}

		if k.Spec.JWTSigningMethod == "rsa" {
			asRSA, err := jwt.ParseRSAPublicKeyFromPEM(val)
			if err != nil {
				log.Error("Failed to deccode JWT to RSA type")
				return nil, err
			}
			return asRSA, nil
		}

		return val, nil
	})

	if err == nil && token.Valid {
		// Token is valid - let's move on

		// Are we mapping to a central JWT Secret?
		if k.Spec.JWTSource != "" {
			return k.processCentralisedJWT(r, token)
		}

		// No, let's try one-to-one mapping
		return k.processOneToOneTokenMap(r, token)
	}
	logEntry := getLogEntryForRequest(r, "", nil)
	logEntry.Info("Attempted JWT access with non-existent key.")

	if err != nil {
		logEntry.Error("JWT validation error: ", err)
	}

	k.reportLoginFailure(tykId, r)
	return errors.New("Key not authorized"), 403
}

func (k *JWTMiddleware) setContextVars(r *http.Request, token *jwt.Token) {
	// Flatten claims and add to context
	if !k.Spec.EnableContextVars {
		return
	}
	if cnt := ctxGetData(r); cnt != nil {
		claimPrefix := "jwt_claims_"

		for claimName, claimValue := range token.Claims.(jwt.MapClaims) {
			claim := claimPrefix + claimName
			cnt[claim] = claimValue
		}

		// Key data
		cnt["token"] = ctxGetAuthToken(r)

		ctxSetData(r, cnt)
	}
}

func generateSessionFromPolicy(policyID, orgID string, enforceOrg bool) (user.SessionState, error) {
	policiesMu.RLock()
	policy, ok := policiesByID[policyID]
	policiesMu.RUnlock()
	session := user.SessionState{}
	if !ok {
		return session, errors.New("Policy not found")
	}
	// Check ownership, policy org owner must be the same as API,
	// otherwise youcould overwrite a session key with a policy from a different org!

	if enforceOrg {
		if policy.OrgID != orgID {
			log.Error("Attempting to apply policy from different organisation to key, skipping")
			return session, errors.New("Key not authorized: no matching policy")
		}
	} else {
		// Org isn;t enforced, so lets use the policy baseline
		orgID = policy.OrgID
	}

	session.SetPolicies(policyID)
	session.OrgID = orgID
	session.Allowance = policy.Rate // This is a legacy thing, merely to make sure output is consistent. Needs to be purged
	session.Rate = policy.Rate
	session.Per = policy.Per
	session.QuotaMax = policy.QuotaMax
	session.QuotaRenewalRate = policy.QuotaRenewalRate
	session.AccessRights = policy.AccessRights
	session.HMACEnabled = policy.HMACEnabled
	session.IsInactive = policy.IsInactive
	session.Tags = policy.Tags

	if policy.KeyExpiresIn > 0 {
		session.Expires = time.Now().Unix() + policy.KeyExpiresIn
	}

	return session, nil
}

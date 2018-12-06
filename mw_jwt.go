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
	"github.com/pmylund/go-cache"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"
)

type JWTMiddleware struct {
	BaseMiddleware
}

const (
	KID       = "kid"
	SUB       = "sub"
	HMACSign  = "hmac"
	RSASign   = "rsa"
	ECDSASign = "ecdsa"
)

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
		k.Logger().Debug("Creating JWK Cache")
		JWKCache = cache.New(240*time.Second, 30*time.Second)
	}

	var jwkSet JWKs
	cachedJWK, found := JWKCache.Get(k.Spec.APIID)
	if !found {
		// Get the JWK
		k.Logger().Debug("Pulling JWK")
		resp, err := http.Get(url)
		if err != nil {
			k.Logger().WithError(err).Error("Failed to get resource URL")
			return nil, err
		}
		defer resp.Body.Close()

		// Decode it
		if err := json.NewDecoder(resp.Body).Decode(&jwkSet); err != nil {
			k.Logger().WithError(err).Error("Failed to decode body JWK")
			return nil, err
		}

		// Cache it
		k.Logger().Debug("Caching JWK")
		JWKCache.Set(k.Spec.APIID, jwkSet, cache.DefaultExpiration)
	} else {
		jwkSet = cachedJWK.(JWKs)
	}

	k.Logger().Debug("Checking JWKs...")
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
			k.Logger().Debug("Found cert! Replying...")
			k.Logger().Debug("Cert was: ", string(decodedCert))
			return decodedCert, nil
		}
		return nil, errors.New("no certificates in JWK")
	}

	return nil, errors.New("No matching KID could be found")
}

func (k *JWTMiddleware) getIdentityFromToken(token *jwt.Token) (string, error) {
	// Check which claim is used for the id - kid or sub header
	// If is not supposed to ignore KID - will use this as ID if not empty
	if !k.Spec.APIDefinition.JWTSkipKid {
		if tykId, idFound := token.Header[KID].(string); idFound {
			k.Logger().Debug("Found: ", tykId)
			return tykId, nil
		}
	}
	// In case KID was empty or was set to ignore KID ==> Will try to get the Id from JWTIdentityBaseField or fallback to 'sub'
	tykId, err := k.getUserIdFromClaim(token.Claims.(jwt.MapClaims))
	return tykId, err
}

func (k *JWTMiddleware) getSecretToVerifySignature(r *http.Request, token *jwt.Token) ([]byte, error) {
	config := k.Spec.APIDefinition
	// Check for central JWT source
	if config.JWTSource != "" {
		// Is it a URL?
		if httpScheme.MatchString(config.JWTSource) {
			secret, err := k.getSecretFromURL(config.JWTSource, token.Header[KID].(string), k.Spec.JWTSigningMethod)
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
			secret, err := k.getSecretFromURL(string(decodedCert), token.Header[KID].(string), k.Spec.JWTSigningMethod)
			if err != nil {
				return nil, err
			}

			return secret, nil
		}

		return decodedCert, nil // Returns the decoded secret
	}

	// If we are here, there's no central JWT source

	// Get the ID from the token (in KID header or configured claim or SUB claim)
	tykId, err := k.getIdentityFromToken(token)
	if err != nil {
		return nil, err
	}

	// Couldn't base64 decode the kid, so lets try it raw
	k.Logger().Debug("Getting key: ", tykId)
	session, rawKeyExists := k.CheckSessionAndIdentityForValidKey(tykId, r)
	if !rawKeyExists {
		return nil, errors.New("token invalid, key not found")
	}
	return []byte(session.JWTData.Secret), nil
}

func (k *JWTMiddleware) getPolicyIDFromToken(claims jwt.MapClaims) (string, bool) {
	policyID, foundPolicy := claims[k.Spec.JWTPolicyFieldName].(string)
	if !foundPolicy {
		k.Logger().Error("Could not identify a policy to apply to this token from field!")
		return "", false
	}

	return policyID, true
}

func (k *JWTMiddleware) getBasePolicyID(r *http.Request, claims jwt.MapClaims) (string, bool) {
	if k.Spec.JWTPolicyFieldName != "" {
		return k.getPolicyIDFromToken(claims)
	} else if k.Spec.JWTClientIDBaseField != "" {
		clientID, clientIDFound := claims[k.Spec.JWTClientIDBaseField].(string)
		if !clientIDFound {
			k.Logger().Error("Could not identify a policy to apply to this token from field!")
			return "", false
		}

		// Check for a regular token that matches this client ID
		clientSession, exists := k.CheckSessionAndIdentityForValidKey(clientID, r)
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

func (k *JWTMiddleware) getUserIdFromClaim(claims jwt.MapClaims) (string, error) {
	var userId string
	var found = false

	if k.Spec.JWTIdentityBaseField != "" {
		if userId, found = claims[k.Spec.JWTIdentityBaseField].(string); found {
			if len(userId) > 0 {
				k.Logger().WithField("userId", userId).Debug("Found User Id in Base Field")
				return userId, nil
			}
			message := "found an empty user ID in predefined base field claim " + k.Spec.JWTIdentityBaseField
			k.Logger().Error(message)
			return "", errors.New(message)
		}

		if !found {
			k.Logger().WithField("Base Field", k.Spec.JWTIdentityBaseField).Warning("Base Field claim not found, trying to find user ID in 'sub' claim.")
		}
	}

	if userId, found = claims[SUB].(string); found {
		if len(userId) > 0 {
			k.Logger().WithField("userId", userId).Debug("Found User Id in 'sub' claim")
			return userId, nil
		}
		message := "found an empty user ID in sub claim"
		k.Logger().Error(message)
		return "", errors.New(message)
	}

	message := "no suitable claims for user ID were found"
	k.Logger().Error(message)
	return "", errors.New(message)
}

func getScopeFromClaim(claims jwt.MapClaims, scopeClaimName string) []string {
	// get claim with scopes and turn it into slice of strings
	if scope, found := claims[scopeClaimName].(string); found {
		return strings.Split(scope, " ") // by standard is space separated list of values
	}

	// claim with scopes is optional so return nothing if it is not present
	return nil
}

func mapScopeToPolicies(mapping map[string]string, scope []string) []string {
	polIDs := []string{}

	// add all policies matched from scope-policy mapping
	policiesToApply := map[string]bool{}
	for _, scopeItem := range scope {
		if policyID, ok := mapping[scopeItem]; ok {
			policiesToApply[policyID] = true
		}
	}
	for id := range policiesToApply {
		polIDs = append(polIDs, id)
	}

	return polIDs
}

// processCentralisedJWT Will check a JWT token centrally against the secret stored in the API Definition.
func (k *JWTMiddleware) processCentralisedJWT(r *http.Request, token *jwt.Token) (error, int) {
	k.Logger().Debug("JWT authority is centralised")

	claims := token.Claims.(jwt.MapClaims)
	baseFieldData, err := k.getUserIdFromClaim(claims)
	if err != nil {
		k.reportLoginFailure("[NOT FOUND]", r)
		return err, http.StatusForbidden
	}

	// Generate a virtual token
	data := []byte(baseFieldData)
	keyID := fmt.Sprintf("%x", md5.Sum(data))
	sessionID := generateToken(k.Spec.OrgID, keyID)

	k.Logger().Debug("JWT Temporary session ID is: ", sessionID)

	session, exists := k.CheckSessionAndIdentityForValidKey(sessionID, r)
	if !exists {
		// Create it
		k.Logger().Debug("Key does not exist, creating")
		session = user.SessionState{}

		// We need a base policy as a template, either get it from the token itself OR a proxy client ID within Tyk
		basePolicyID, foundPolicy := k.getBasePolicyID(r, claims)
		if !foundPolicy {
			k.reportLoginFailure(baseFieldData, r)
			return errors.New("Key not authorized: no matching policy found"), http.StatusForbidden
		}

		newSession, err := generateSessionFromPolicy(basePolicyID,
			k.Spec.OrgID,
			true)

		// apply policies from scope if scope-to-policy mapping is specified for this API
		if k.Spec.JWTScopeToPolicyMapping != nil {
			if scope := getScopeFromClaim(claims, "scope"); scope != nil {
				polIDs := []string{
					basePolicyID, // add base policy as a first one
				}

				// add all policies matched from scope-policy mapping
				mappedPolIDs := mapScopeToPolicies(k.Spec.JWTScopeToPolicyMapping, scope)

				polIDs = append(polIDs, mappedPolIDs...)
				newSession.SetPolicies(polIDs...)

				// multiple policies assigned to a key, check if it is applicable
				if err := k.ApplyPolicies(sessionID, &newSession); err != nil {
					k.reportLoginFailure(baseFieldData, r)
					k.Logger().WithError(err).Error("Could not several policies from scope-claim mapping to JWT to session")
					return errors.New("Key not authorized: could not apply several policies"), http.StatusForbidden
				}
			}
		}

		if err != nil {
			k.reportLoginFailure(baseFieldData, r)
			k.Logger().Error("Could not find a valid policy to apply to this token!")
			return errors.New("Key not authorized: no matching policy"), http.StatusForbidden
		}
		//override session expiry with JWT if longer lived
		if f, ok := claims["exp"].(float64); ok {
			if int64(f)-newSession.Expires > 0 {
				newSession.Expires = int64(f)
			}
		}

		session = newSession
		session.MetaData = map[string]interface{}{"TykJWTSessionID": sessionID}
		session.Alias = baseFieldData

		// Update the session in the session manager in case it gets called again
		k.Logger().Debug("Policy applied to key")

		switch k.Spec.BaseIdentityProvidedBy {
		case apidef.JWTClaim, apidef.UnsetAuth:
			ctxSetSession(r, &session, sessionID, true)
		}
		ctxSetJWTContextVars(k.Spec, r, token)
		return nil, http.StatusOK
	} else if k.Spec.JWTPolicyFieldName != "" {
		// extract policy ID from JWT token
		policyID, foundPolicy := k.getPolicyIDFromToken(claims)
		if !foundPolicy {
			k.reportLoginFailure(baseFieldData, r)
			return errors.New("key not authorized: no matching policy claim found"), http.StatusForbidden
		}
		// check if we received a valid policy ID in claim
		policiesMu.RLock()
		policy, ok := policiesByID[policyID]
		policiesMu.RUnlock()
		if !ok {
			k.reportLoginFailure(baseFieldData, r)
			k.Logger().Error("Policy ID found in token is invalid!")
			return errors.New("key not authorized: no matching policy"), http.StatusForbidden
		}
		// check if token for this session was switched to another valid policy
		pols := session.PolicyIDs()
		if len(pols) == 0 {
			k.reportLoginFailure(baseFieldData, r)
			k.Logger().Error("No policies for the found session. Failing Request.")
			return errors.New("key not authorized: no matching policy found"), http.StatusForbidden
		}
		if pols[0] != policyID { // switch session to new policy and update session storage and cache
			// check ownership before updating session
			if policy.OrgID != k.Spec.OrgID {
				k.reportLoginFailure(baseFieldData, r)
				k.Logger().Error("Policy ID found in token is invalid (wrong ownership)!")
				return errors.New("Key not authorized: no matching policy"), http.StatusForbidden
			}
			// apply new policy to session and update session
			session.SetPolicies(policyID)
			if err := k.ApplyPolicies(sessionID, &session); err != nil {
				k.reportLoginFailure(baseFieldData, r)
				k.Logger().WithError(err).Error("Could not apply new policy from JWT to session")
				return errors.New("Key not authorized: could not apply new policy"), http.StatusForbidden
			}

			//override session expiry with JWT if longer lived
			if f, ok := claims["exp"].(float64); ok {
				if int64(f)-session.Expires > 0 {
					session.Expires = int64(f)
				}
			}

			go SessionCache.Set(session.KeyHash(), session, cache.DefaultExpiration)
		}
	}

	k.Logger().Debug("Key found")
	switch k.Spec.BaseIdentityProvidedBy {
	case apidef.JWTClaim, apidef.UnsetAuth:
		ctxSetSession(r, &session, sessionID, false)
	}
	ctxSetJWTContextVars(k.Spec, r, token)
	return nil, http.StatusOK
}

func (k *JWTMiddleware) reportLoginFailure(tykId string, r *http.Request) {
	// Fire Authfailed Event
	AuthFailed(k, r, tykId)

	// Report in health check
	reportHealthValue(k.Spec, KeyFailure, "1")
}

func (k *JWTMiddleware) processOneToOneTokenMap(r *http.Request, token *jwt.Token) (error, int) {
	// Get the ID from the token
	tykId, err := k.getIdentityFromToken(token)
	if err != nil {
		k.reportLoginFailure(tykId, r)
		return err, http.StatusNotFound
	}

	k.Logger().Debug("Using raw key ID: ", tykId)
	session, exists := k.CheckSessionAndIdentityForValidKey(tykId, r)
	if !exists {
		k.reportLoginFailure(tykId, r)
		return errors.New("Key not authorized"), http.StatusForbidden
	}

	k.Logger().Debug("Raw key ID found.")
	ctxSetSession(r, &session, tykId, false)
	ctxSetJWTContextVars(k.Spec, r, token)
	return nil, http.StatusOK
}

func (k *JWTMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	logger := k.Logger()
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
		logger.Info("Attempted access with malformed header, no JWT auth header found.")

		log.Debug("Looked in: ", config.AuthHeaderName)
		log.Debug("Raw data was: ", rawJWT)
		log.Debug("Headers are: ", r.Header)

		k.reportLoginFailure(tykId, r)
		return errors.New("Authorization field missing"), http.StatusBadRequest
	}

	// enable bearer token format
	rawJWT = stripBearer(rawJWT)

	// Use own validation logic, see below
	parser := &jwt.Parser{SkipClaimsValidation: true}

	// Verify the token
	token, err := parser.Parse(rawJWT, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		switch k.Spec.JWTSigningMethod {
		case HMACSign:
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v and not HMAC signature", token.Header["alg"])
			}
		case RSASign:
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v and not RSA signature", token.Header["alg"])
			}
		case ECDSASign:
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v and not ECDSA signature", token.Header["alg"])
			}
		default:
			logger.Warning("No signing method found in API Definition, defaulting to HMAC signature")
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
		}

		val, err := k.getSecretToVerifySignature(r, token)
		if err != nil {
			k.Logger().WithError(err).Error("Couldn't get token")
			return nil, err
		}

		if k.Spec.JWTSigningMethod == RSASign {
			asRSA, err := jwt.ParseRSAPublicKeyFromPEM(val)
			if err != nil {
				logger.WithError(err).Error("Failed to decode JWT to RSA type")
				return nil, err
			}
			return asRSA, nil
		}

		return val, nil
	})

	if err == nil && token.Valid {
		if jwtErr := k.timeValidateJWTClaims(token.Claims.(jwt.MapClaims)); jwtErr != nil {
			return errors.New("Key not authorized: " + jwtErr.Error()), http.StatusUnauthorized
		}

		// Token is valid - let's move on

		// Are we mapping to a central JWT Secret?
		if k.Spec.JWTSource != "" {
			return k.processCentralisedJWT(r, token)
		}

		// No, let's try one-to-one mapping
		return k.processOneToOneTokenMap(r, token)
	}

	logger.Info("Attempted JWT access with non-existent key.")
	k.reportLoginFailure(tykId, r)
	if err != nil {
		logger.WithError(err).Error("JWT validation error")
		return errors.New("Key not authorized:" + err.Error()), http.StatusForbidden
	}
	return errors.New("Key not authorized"), http.StatusForbidden
}

func (k *JWTMiddleware) timeValidateJWTClaims(c jwt.MapClaims) *jwt.ValidationError {
	vErr := new(jwt.ValidationError)
	now := time.Now().Unix()
	// The claims below are optional, by default, so if they are set to the
	// default value in Go, let's not fail the verification for them.
	if !c.VerifyExpiresAt(now-int64(k.Spec.JWTExpiresAtValidationSkew), false) {
		vErr.Inner = errors.New("token has expired")
		vErr.Errors |= jwt.ValidationErrorExpired
	}

	if c.VerifyIssuedAt(now+int64(k.Spec.JWTIssuedAtValidationSkew), false) == false {
		vErr.Inner = errors.New("token used before issued")
		vErr.Errors |= jwt.ValidationErrorIssuedAt
	}

	if c.VerifyNotBefore(now+int64(k.Spec.JWTNotBeforeValidationSkew), false) == false {
		vErr.Inner = errors.New("token is not valid yet")
		vErr.Errors |= jwt.ValidationErrorNotValidYet
	}

	if vErr.Errors == 0 {
		return nil
	}

	return vErr
}

func ctxSetJWTContextVars(s *APISpec, r *http.Request, token *jwt.Token) {
	// Flatten claims and add to context
	if !s.EnableContextVars {
		return
	}
	if cnt := ctxGetData(r); cnt != nil {
		claimPrefix := "jwt_claims_"

		for claimName, claimValue := range token.Header {
			claim := claimPrefix + claimName
			cnt[claim] = claimValue
		}

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
	session.AccessRights = make(map[string]user.AccessDefinition)
	for apiID, access := range policy.AccessRights {
		session.AccessRights[apiID] = access
	}
	session.HMACEnabled = policy.HMACEnabled
	session.IsInactive = policy.IsInactive
	session.Tags = policy.Tags

	if policy.KeyExpiresIn > 0 {
		session.Expires = time.Now().Unix() + policy.KeyExpiresIn
	}

	return session, nil
}

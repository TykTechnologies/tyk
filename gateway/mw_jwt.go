package gateway

import (
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lonelycode/osin"
	cache "github.com/pmylund/go-cache"
	jose "github.com/square/go-jose"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/storage"

	"github.com/TykTechnologies/tyk/user"
)

type JWTMiddleware struct {
	JWTBase
}

const (
	KID       = "kid"
	SUB       = "sub"
	HMACSign  = "hmac"
	RSASign   = "rsa"
	ECDSASign = "ecdsa"
)

const UnexpectedSigningMethod = "Unexpected signing method"

var (
	// List of common OAuth Client ID claims used by IDPs:
	oauthClientIDClaims = []string{
		"clientId",  // Keycloak
		"cid",       // OKTA
		"client_id", // Gluu
	}
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

func parseJWK(buf []byte) (*jose.JSONWebKeySet, error) {
	var j jose.JSONWebKeySet
	err := json.Unmarshal(buf, &j)
	if err != nil {
		return nil, err
	}
	return &j, nil
}

func (k *JWTMiddleware) getPolicyIDFromToken(claims jwt.MapClaims) (string, bool) {
	policyID, foundPolicy := claims[k.Spec.JWTPolicyFieldName].(string)
	if !foundPolicy {
		k.Logger().Debugf("Could not identify a policy to apply to this token from field: %s", k.Spec.JWTPolicyFieldName)
		return "", false
	}

	if policyID == "" {
		k.Logger().Errorf("Policy field %s has empty value", k.Spec.JWTPolicyFieldName)
		return "", false
	}

	return policyID, true
}

func (k *JWTMiddleware) getBasePolicyID(r *http.Request, claims jwt.MapClaims) (policyID string, found bool) {
	if k.Spec.JWTPolicyFieldName != "" {
		policyID, found = k.getPolicyIDFromToken(claims)
		return
	} else if k.Spec.JWTClientIDBaseField != "" {
		clientID, clientIDFound := claims[k.Spec.JWTClientIDBaseField].(string)
		if !clientIDFound {
			k.Logger().Debug("Could not identify a policy to apply to this token from field")
			return
		}

		// Check for a regular token that matches this client ID
		clientSession, exists := k.CheckSessionAndIdentityForValidKey(clientID, r)
		clientID = clientSession.KeyID
		if !exists {
			return
		}

		pols := clientSession.PolicyIDs()
		if len(pols) < 1 {
			return
		}

		// Use the policy from the client ID
		return pols[0], true
	}

	return
}

func toStrings(v interface{}) []string {
	switch e := v.(type) {
	case string:
		return strings.Split(e, " ")
	case []interface{}:
		var r []string
		for _, x := range e {
			r = append(r, toStrings(x)...)
		}
		return r
	}
	return nil
}

func nestedMapLookup(m map[string]interface{}, ks ...string) interface{} {
	var c interface{} = m
	for _, k := range ks {
		if _, ok := c.(map[string]interface{}); !ok {
			//fmt.Errorf("key not found; remaining keys: %v", ks)
			return nil
		}
		c = getMapContext(c, k)
	}
	return c
}

func getMapContext(m interface{}, k string) (rval interface{}) {
	switch e := m.(type) {
	case map[string]interface{}:
		return e[k]
	default:
		return e
	}
}

func getScopeFromClaim(claims jwt.MapClaims, scopeClaimName string) []string {
	lookedUp := nestedMapLookup(claims, strings.Split(scopeClaimName, ".")...)

	return toStrings(lookedUp)
}

func mapScopeToPolicies(mapping map[string]string, scope []string) []string {
	polIDs := []string{}

	// add all policies matched from scope-policy mapping
	policiesToApply := map[string]bool{}
	for _, scopeItem := range scope {
		if policyID, ok := mapping[scopeItem]; ok {
			policiesToApply[policyID] = true
			log.Debugf("Found a matching policy for scope item: %s", scopeItem)
		} else {
			log.Errorf("Couldn't find a matching policy for scope item: %s", scopeItem)
		}
	}
	for id := range policiesToApply {
		polIDs = append(polIDs, id)
	}

	return polIDs
}

func (k *JWTMiddleware) getOAuthClientIDFromClaim(claims jwt.MapClaims) string {
	for _, claimName := range oauthClientIDClaims {
		if val, ok := claims[claimName]; ok {
			return val.(string)
		}
	}
	return ""
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

	// Get the OAuth client ID if available:
	oauthClientID := k.getOAuthClientIDFromClaim(claims)

	// Generate a virtual token
	data := []byte(baseFieldData)
	keyID := fmt.Sprintf("%x", md5.Sum(data))
	sessionID := k.Gw.generateToken(k.Spec.OrgID, keyID)
	updateSession := false

	k.Logger().Debug("JWT Temporary session ID is: ", sessionID)

	// CheckSessionAndIdentityForValidKey returns a session with keyID populated
	session, exists := k.CheckSessionAndIdentityForValidKey(sessionID, r)

	sessionID = session.KeyID
	isDefaultPol := false
	basePolicyID := ""
	foundPolicy := false
	if !exists {
		// Create it
		k.Logger().Debug("Key does not exist, creating")

		// We need a base policy as a template, either get it from the token itself OR a proxy client ID within Tyk
		basePolicyID, foundPolicy = k.getBasePolicyID(r, claims)
		if !foundPolicy {
			if len(k.Spec.JWTDefaultPolicies) == 0 {
				k.reportLoginFailure(baseFieldData, r)
				return errors.New("key not authorized: no matching policy found"), http.StatusForbidden
			} else {
				isDefaultPol = true
				basePolicyID = k.Spec.JWTDefaultPolicies[0]
			}
		}

		session, err = k.Gw.generateSessionFromPolicy(basePolicyID,
			k.Spec.OrgID,
			true)

		// If base policy is one of the defaults, apply other ones as well
		if isDefaultPol {
			for _, pol := range k.Spec.JWTDefaultPolicies {
				if !contains(session.ApplyPolicies, pol) {
					session.ApplyPolicies = append(session.ApplyPolicies, pol)
				}
			}
		}

		if err := k.ApplyPolicies(&session); err != nil {
			return errors.New("failed to create key: " + err.Error()), http.StatusInternalServerError
		}

		if err != nil {
			k.reportLoginFailure(baseFieldData, r)
			k.Logger().Error("Could not find a valid policy to apply to this token!")
			return errors.New("key not authorized: no matching policy"), http.StatusForbidden
		}

		//override session expiry with JWT if longer lived
		if f, ok := claims["exp"].(float64); ok {
			if int64(f)-session.Expires > 0 {
				session.Expires = int64(f)
			}
		}

		session.MetaData = map[string]interface{}{"TykJWTSessionID": sessionID}
		session.Alias = baseFieldData

		// Update the session in the session manager in case it gets called again
		updateSession = true
		k.Logger().Debug("Policy applied to key")
	} else {
		// extract policy ID from JWT token
		basePolicyID, foundPolicy = k.getBasePolicyID(r, claims)
		if !foundPolicy {
			if len(k.Spec.JWTDefaultPolicies) == 0 {
				k.reportLoginFailure(baseFieldData, r)
				return errors.New("key not authorized: no matching policy found"), http.StatusForbidden
			} else {
				isDefaultPol = true
				basePolicyID = k.Spec.JWTDefaultPolicies[0]
			}
		}
		// check if we received a valid policy ID in claim
		k.Gw.policiesMu.RLock()
		policy, ok := k.Gw.policiesByID[basePolicyID]
		k.Gw.policiesMu.RUnlock()
		if !ok {
			k.reportLoginFailure(baseFieldData, r)
			k.Logger().Error("Policy ID found is invalid!")
			return errors.New("key not authorized: no matching policy"), http.StatusForbidden
		}
		// check if token for this session was switched to another valid policy
		pols := session.PolicyIDs()
		if len(pols) == 0 {
			k.reportLoginFailure(baseFieldData, r)
			k.Logger().Error("No policies for the found session. Failing Request.")
			return errors.New("key not authorized: no matching policy found"), http.StatusForbidden
		}

		defaultPolicyListChanged := false

		if isDefaultPol {
			// check a policy is removed/added from/to default policies

			for _, pol := range session.PolicyIDs() {
				if !contains(k.Spec.JWTDefaultPolicies, pol) && basePolicyID != pol {
					defaultPolicyListChanged = true
				}
			}

			for _, defPol := range k.Spec.JWTDefaultPolicies {
				if !contains(session.PolicyIDs(), defPol) {
					defaultPolicyListChanged = true
				}
			}
		}

		if !contains(pols, basePolicyID) || defaultPolicyListChanged {
			if policy.OrgID != k.Spec.OrgID {
				k.reportLoginFailure(baseFieldData, r)
				k.Logger().Error("Policy ID found is invalid (wrong ownership)!")
				return errors.New("key not authorized: no matching policy"), http.StatusForbidden
			}
			// apply new policy to session and update session
			updateSession = true
			session.SetPolicies(basePolicyID)

			if isDefaultPol {
				for _, pol := range k.Spec.JWTDefaultPolicies {
					if !contains(session.ApplyPolicies, pol) {
						session.ApplyPolicies = append(session.ApplyPolicies, pol)
					}
				}
			}

			if err := k.ApplyPolicies(&session); err != nil {
				k.reportLoginFailure(baseFieldData, r)
				k.Logger().WithError(err).Error("Could not apply new policy to session")
				return errors.New("key not authorized: could not apply new policy"), http.StatusForbidden
			}
		}

		//override session expiry with JWT if longer lived
		if f, ok := claims["exp"].(float64); ok {
			if int64(f)-session.Expires > 0 {
				session.Expires = int64(f)
				updateSession = true
			}
		}
	}

	// apply policies from scope if scope-to-policy mapping is specified for this API
	if len(k.Spec.Scopes.JWT.ScopeToPolicy) != 0 {
		scopeClaimName := k.Spec.Scopes.JWT.ScopeClaimName
		if scopeClaimName == "" {
			scopeClaimName = "scope"
		}

		if scope := getScopeFromClaim(claims, scopeClaimName); scope != nil {
			polIDs := []string{
				basePolicyID, // add base policy as a first one
			}

			// // If specified, scopes should not use default policy
			if isDefaultPol {
				polIDs = []string{}
			}

			// add all policies matched from scope-policy mapping
			mappedPolIDs := mapScopeToPolicies(k.Spec.Scopes.JWT.ScopeToPolicy, scope)
			if len(mappedPolIDs) > 0 {
				k.Logger().Debugf("Identified policy(s) to apply to this token from scope claim: %s", scopeClaimName)
			} else {
				k.Logger().Errorf("Couldn't identify policy(s) to apply to this token from scope claim: %s", scopeClaimName)
			}

			polIDs = append(polIDs, mappedPolIDs...)
			if len(polIDs) == 0 {
				k.reportLoginFailure(baseFieldData, r)
				k.Logger().Error("no matching policy found in scope claim")
				return errors.New("key not authorized: no matching policy found in scope claim"), http.StatusForbidden
			}

			// check if we need to update session
			if !updateSession {
				updateSession = !session.PoliciesEqualTo(polIDs)
			}

			session.SetPolicies(polIDs...)

			// multiple policies assigned to a key, check if it is applicable
			if err := k.ApplyPolicies(&session); err != nil {
				k.reportLoginFailure(baseFieldData, r)
				k.Logger().WithError(err).Error("Could not several policies from scope-claim mapping to JWT to session")
				return errors.New("key not authorized: could not apply several policies"), http.StatusForbidden
			}

		}
	}

	session.OauthClientID = oauthClientID
	if session.OauthClientID != "" {
		// Initialize the OAuthManager if empty:
		if k.Spec.OAuthManager == nil {
			prefix := generateOAuthPrefix(k.Spec.APIID)
			storageManager := k.Gw.getGlobalMDCBStorageHandler(prefix, false)
			storageManager.Connect()
			k.Spec.OAuthManager = &OAuthManager{
				OsinServer: k.Gw.TykOsinNewServer(&osin.ServerConfig{},
					&RedisOsinStorageInterface{
						storageManager,
						k.Gw.GlobalSessionManager,
						&storage.RedisCluster{KeyPrefix: prefix, HashKeys: false, RedisController: k.Gw.RedisController},
						k.Spec.OrgID,
						k.Gw,
					}),
			}
		}

		// Retrieve OAuth client data from storage and inject developer ID into the session object:
		client, err := k.Spec.OAuthManager.OsinServer.Storage.GetClient(oauthClientID)
		if err == nil {
			userData := client.GetUserData()
			if userData != nil {
				data, ok := userData.(map[string]interface{})
				if ok {
					developerID, keyFound := data["tyk_developer_id"].(string)
					if keyFound {
						session.MetaData["tyk_developer_id"] = developerID
					}
				}
			}
		} else {
			k.Logger().WithError(err).Error("Couldn't get OAuth client")
		}
	}

	// ensure to set the sessionID
	session.KeyID = sessionID
	k.Logger().Debug("Key found")
	switch k.Spec.BaseIdentityProvidedBy {
	case apidef.JWTClaim, apidef.UnsetAuth:
		ctxSetSession(r, &session, updateSession, k.Gw.GetConfig().HashKeys)
		if updateSession {
			k.Gw.SessionCache.Set(session.KeyHash(), session.Clone(), cache.DefaultExpiration)
		}
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
	tykId = session.KeyID

	if !exists {
		k.reportLoginFailure(tykId, r)
		return errors.New("Key not authorized"), http.StatusForbidden
	}

	k.Logger().Debug("Raw key ID found.")
	ctxSetSession(r, &session, false, k.Gw.GetConfig().HashKeys)
	ctxSetJWTContextVars(k.Spec, r, token)
	return nil, http.StatusOK
}

// getAuthType overrides BaseMiddleware.getAuthType.
func (k *JWTMiddleware) getAuthType() string {
	return apidef.JWTType
}

func (k *JWTMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if ctxGetRequestStatus(r) == StatusOkAndIgnore {
		return nil, http.StatusOK
	}

	logger := k.Logger()
	var tykId string

	rawJWT, config := k.getAuthToken(k.getAuthType(), r)

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
	token, err := parser.Parse(rawJWT, k.ParseJWTHook(r, true))

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
		errorDetails := strings.Split(err.Error(), ":")
		if errorDetails[0] == UnexpectedSigningMethod {
			return errors.New(MsgKeyNotAuthorizedUnexpectedSigningMethod), http.StatusForbidden
		}
	}
	return errors.New("Key not authorized"), http.StatusForbidden
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

func (gw *Gateway) generateSessionFromPolicy(policyID, orgID string, enforceOrg bool) (user.SessionState, error) {
	gw.policiesMu.RLock()
	policy, ok := gw.policiesByID[policyID]
	gw.policiesMu.RUnlock()
	session := user.SessionState{}

	if !ok {
		return session.Clone(), errors.New("Policy not found")
	}
	// Check ownership, policy org owner must be the same as API,
	// otherwise you could overwrite a session key with a policy from a different org!

	if enforceOrg {
		if policy.OrgID != orgID {
			log.Error("Attempting to apply policy from different organisation to key, skipping")
			return session.Clone(), errors.New("Key not authorized: no matching policy")
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
	session.ThrottleInterval = policy.ThrottleInterval
	session.ThrottleRetryLimit = policy.ThrottleRetryLimit
	session.MaxQueryDepth = policy.MaxQueryDepth
	session.QuotaMax = policy.QuotaMax
	session.QuotaRenewalRate = policy.QuotaRenewalRate
	session.AccessRights = make(map[string]user.AccessDefinition)
	for apiID, access := range policy.AccessRights {
		session.AccessRights[apiID] = access
	}
	session.HMACEnabled = policy.HMACEnabled
	session.EnableHTTPSignatureValidation = policy.EnableHTTPSignatureValidation
	session.IsInactive = policy.IsInactive
	session.Tags = policy.Tags

	if policy.KeyExpiresIn > 0 {
		session.Expires = time.Now().Unix() + policy.KeyExpiresIn
	}

	return session.Clone(), nil
}

package gateway

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/golang-jwt/jwt/v4"
	"github.com/lonelycode/osin"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"

	"github.com/TykTechnologies/tyk/internal/cache"
)

type JWTMiddleware struct {
	*BaseMiddleware
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

	ErrNoSuitableUserIDClaimFound = errors.New("no suitable claims for user ID were found")
	ErrEmptyUserIDInSubClaim      = errors.New("found an empty user ID in sub claim")
)

func (k *JWTMiddleware) Name() string {
	return "JWTMiddleware"
}

func (k *JWTMiddleware) EnabledForSpec() bool {
	return k.Spec.EnableJWT
}

var JWKCache cache.Repository = cache.New(240, 30)

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

func (k *JWTMiddleware) legacyGetSecretFromURL(url, kid, keyType string) (interface{}, error) {
	var client http.Client
	client.Transport = &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: k.Gw.GetConfig().JWTSSLInsecureSkipVerify},
	}

	var jwkSet JWKs
	cachedJWK, found := JWKCache.Get("legacy-" + k.Spec.APIID)
	if !found {
		resp, err := client.Get(url)
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

		JWKCache.Set("legacy-"+k.Spec.APIID, jwkSet, cache.DefaultExpiration)
	} else {
		jwkSet = cachedJWK.(JWKs)
	}

	for _, val := range jwkSet.Keys {
		if val.KID != kid || strings.ToLower(val.Kty) != strings.ToLower(keyType) {
			continue
		}
		if len(val.X5c) > 0 {
			// Use the first cert only
			decodedCert, err := base64.StdEncoding.DecodeString(val.X5c[0])
			if !bytes.Contains(decodedCert, []byte("-----")) {
				return nil, errors.New("No legacy public keys found")
			}
			if err != nil {
				return nil, err
			}
			return ParseRSAPublicKey(decodedCert)
		}
		return nil, errors.New("no certificates in JWK")
	}

	return nil, errors.New("No matching KID could be found")
}

func (k *JWTMiddleware) getSecretFromURL(url string, kidVal interface{}, keyType string) (interface{}, error) {
	kid, ok := kidVal.(string)
	if !ok {
		return nil, ErrKIDNotAString
	}

	var (
		jwkSet *jose.JSONWebKeySet
		err    error
	)

	cachedJWK, found := JWKCache.Get(k.Spec.APIID)
	if !found {
		if jwkSet, err = getJWK(url, k.Gw.GetConfig().JWTSSLInsecureSkipVerify); err != nil {
			k.Logger().WithError(err).Info("Failed to decode JWKs body. Trying x5c PEM fallback.")

			key, legacyError := k.legacyGetSecretFromURL(url, kid, keyType)
			if legacyError == nil {
				return key, nil
			}

			return nil, err
		}

		// Cache it
		k.Logger().Debug("Caching JWK")
		JWKCache.Set(k.Spec.APIID, jwkSet, cache.DefaultExpiration)
	} else {
		jwkSet = cachedJWK.(*jose.JSONWebKeySet)
	}
	k.Logger().Debug("Checking JWKs...")
	if keys := jwkSet.Key(kid); len(keys) > 0 {
		return keys[0].Key, nil
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

func (k *JWTMiddleware) getSecretToVerifySignature(r *http.Request, token *jwt.Token) (interface{}, error) {
	config := k.Spec.APIDefinition
	// Check for central JWT source
	if config.JWTSource != "" {
		// Is it a URL?
		if httpScheme.MatchString(config.JWTSource) {
			return k.getSecretFromURL(config.JWTSource, token.Header[KID], k.Spec.JWTSigningMethod)
		}

		// If not, return the actual value
		decodedCert, err := base64.StdEncoding.DecodeString(config.JWTSource)
		if err != nil {
			return nil, err
		}

		// Is decoded url too?
		if httpScheme.MatchString(string(decodedCert)) {
			return k.getSecretFromURL(string(decodedCert), token.Header[KID], k.Spec.JWTSigningMethod)
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
	tykId = session.KeyID
	if !rawKeyExists {
		return nil, errors.New("token invalid, key not found")
	}
	return []byte(session.JWTData.Secret), nil
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

func (k *JWTMiddleware) getUserIdFromClaim(claims jwt.MapClaims) (string, error) {
	return getUserIDFromClaim(claims, k.Spec.JWTIdentityBaseField)
}

func toScopeStringsSlice(v interface{}, scopeSlice *[]string, nested bool) []string {
	if scopeSlice == nil {
		scopeSlice = &[]string{}
	}

	switch e := v.(type) {
	case string:
		if !nested {
			splitStringScopes := strings.Split(e, " ")
			*scopeSlice = append(*scopeSlice, splitStringScopes...)
		} else {
			*scopeSlice = append(*scopeSlice, e)
		}

	case []interface{}:
		for _, scopeElement := range e {
			toScopeStringsSlice(scopeElement, scopeSlice, true)
		}
	}

	return *scopeSlice
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

	return toScopeStringsSlice(lookedUp, nil, false)
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
	if len(k.Spec.GetScopeToPolicyMapping()) != 0 {
		scopeClaimName := k.Spec.GetScopeClaimName()
		if scopeClaimName == "" {
			scopeClaimName = "scope"
		}

		if scope := getScopeFromClaim(claims, scopeClaimName); len(scope) > 0 {
			polIDs := []string{
				basePolicyID, // add base policy as a first one
			}

			// // If specified, scopes should not use default policy
			if isDefaultPol {
				polIDs = []string{}
			}

			// add all policies matched from scope-policy mapping
			mappedPolIDs := mapScopeToPolicies(k.Spec.GetScopeToPolicyMapping(), scope)
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

	oauthClientID := ""
	// Get the OAuth client ID if available:
	if !k.Spec.IDPClientIDMappingDisabled {
		oauthClientID = k.getOAuthClientIDFromClaim(claims)
	}

	if session.OauthClientID != oauthClientID {
		session.OauthClientID = oauthClientID
		updateSession = true
	}

	if !k.Spec.IDPClientIDMappingDisabled && oauthClientID != "" {
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
						&storage.RedisCluster{KeyPrefix: prefix, HashKeys: false, ConnectionHandler: k.Gw.StorageConnectionHandler},
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
					updateSession = session.TagsFromMetadata(data)

					if err := k.ApplyPolicies(&session); err != nil {
						return errors.New("failed to apply policies in session metadata: " + err.Error()), http.StatusInternalServerError
					}
				}
			}
		} else {
			k.Logger().WithError(err).Debug("Couldn't get OAuth client")
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
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())

	// Verify the token
	token, err := parser.Parse(rawJWT, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if err := assertSigningMethod(k.Spec.JWTSigningMethod, token); err != nil {
			return nil, err
		}

		val, err := k.getSecretToVerifySignature(r, token)
		if err != nil {
			k.Logger().WithError(err).Error("Couldn't get token")
			return nil, err
		}

		return parseJWTKey(k.Spec.JWTSigningMethod, val)
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
		errorDetails := strings.Split(err.Error(), ":")
		if errorDetails[0] == UnexpectedSigningMethod {
			return errors.New(MsgKeyNotAuthorizedUnexpectedSigningMethod), http.StatusForbidden
		}
	}
	return errors.New("Key not authorized"), http.StatusForbidden
}

func ParseRSAPublicKey(data []byte) (interface{}, error) {
	input := data
	block, _ := pem.Decode(data)
	if block != nil {
		input = block.Bytes
	}
	var pub interface{}
	var err error
	pub, err = x509.ParsePKIXPublicKey(input)
	if err != nil {
		cert, err0 := x509.ParseCertificate(input)
		if err0 != nil {
			return nil, err0
		}
		pub = cert.PublicKey
		err = nil
	}
	return pub, err
}

func (k *JWTMiddleware) timeValidateJWTClaims(c jwt.MapClaims) *jwt.ValidationError {
	return timeValidateJWTClaims(c, k.Spec.JWTExpiresAtValidationSkew, k.Spec.JWTIssuedAtValidationSkew,
		k.Spec.JWTNotBeforeValidationSkew)
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

// assertSigningMethod asserts the provided signing method with that of jwt.
func assertSigningMethod(signingMethod string, token *jwt.Token) error {
	switch signingMethod {
	case HMACSign:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return fmt.Errorf("%v: %v and not HMAC signature", UnexpectedSigningMethod, token.Header["alg"])
		}
	case RSASign:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return fmt.Errorf("%v: %v and not RSA signature", UnexpectedSigningMethod, token.Header["alg"])
		}
	case ECDSASign:
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return fmt.Errorf("%v: %v and not ECDSA signature", UnexpectedSigningMethod, token.Header["alg"])
		}
	default:
		log.Warning("No signing method found in API Definition, defaulting to HMAC signature")
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return fmt.Errorf("%v: %v", UnexpectedSigningMethod, token.Header["alg"])
		}
	}

	return nil
}

// parseJWTKey parses JWT key based on signing Method
func parseJWTKey(signingMethod string, secret interface{}) (interface{}, error) {
	switch signingMethod {
	case RSASign, ECDSASign:
		switch e := secret.(type) {
		case []byte:
			key, err := ParseRSAPublicKey(e)
			if err != nil {
				log.WithError(err).Error("Failed to decode JWT key")
				return nil, errors.New("Failed to decode JWT key")
			}
			return key, nil
		default:
			// We have already parsed the correct key so we just return it here.No need
			// for checks because they already happened somewhere ele.
			return e, nil
		}

	default:
		return secret, nil
	}
}

// getJWK gets the JWK from URL.
func getJWK(url string, jwtSSLInsecureSkipVerify bool) (*jose.JSONWebKeySet, error) {
	client := http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: jwtSSLInsecureSkipVerify},
		},
	}

	// Get the JWK
	log.Debug("Pulling JWK")
	resp, err := client.Get(url)
	if err != nil {
		log.WithError(err).Error("Failed to get resource URL")
		return nil, err
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).Error("Failed to get read response body")
		return nil, err
	}

	jwkSet, err := parseJWK(buf)
	if err != nil {
		return nil, err
	}

	return jwkSet, nil
}

// timeValidateJWTClaims validates JWT with provided clock skew, to overcome skew occurred with distributed systems.
func timeValidateJWTClaims(c jwt.MapClaims, expiresAt, issuedAt, notBefore uint64) *jwt.ValidationError {
	vErr := new(jwt.ValidationError)
	now := time.Now().Unix()
	// The claims below are optional, by default, so if they are set to the
	// default value in Go, let's not fail the verification for them.
	if !c.VerifyExpiresAt(now-int64(expiresAt), false) {
		vErr.Inner = errors.New("token has expired")
		vErr.Errors |= jwt.ValidationErrorExpired
	}

	if !c.VerifyIssuedAt(now+int64(issuedAt), false) {
		vErr.Inner = errors.New("token used before issued")
		vErr.Errors |= jwt.ValidationErrorIssuedAt
	}

	if !c.VerifyNotBefore(now+int64(notBefore), false) {
		vErr.Inner = errors.New("token is not valid yet")
		vErr.Errors |= jwt.ValidationErrorNotValidYet
	}

	if vErr.Errors == 0 {
		return nil
	}

	return vErr
}

// getUserIDFromClaim parses jwt claims and get the userID from provided identityBaseField.
func getUserIDFromClaim(claims jwt.MapClaims, identityBaseField string) (string, error) {
	var (
		userID string
		found  bool
	)

	if identityBaseField != "" {
		if userID, found = claims[identityBaseField].(string); found {
			if len(userID) > 0 {
				log.WithField("userId", userID).Debug("Found User Id in Base Field")
				return userID, nil
			}

			message := "found an empty user ID in predefined base field claim " + identityBaseField
			log.Error(message)
			return "", errors.New(message)
		}

		if !found {
			log.WithField("Base Field", identityBaseField).Warning("Base Field claim not found, trying to find user ID in 'sub' claim.")
		}
	}

	if userID, found = claims[SUB].(string); found {
		if len(userID) > 0 {
			log.WithField("userId", userID).Debug("Found User Id in 'sub' claim")
			return userID, nil
		}

		log.Error(ErrEmptyUserIDInSubClaim)
		return "", ErrEmptyUserIDInSubClaim
	}

	log.Error(ErrNoSuitableUserIDClaimFound)
	return "", ErrNoSuitableUserIDClaimFound
}

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
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/gorilla/mux"
	"github.com/lonelycode/osin"
	"github.com/ohler55/ojg/jp"
	"github.com/tidwall/gjson"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/cache"
	tykerrors "github.com/TykTechnologies/tyk/internal/errors"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/internal/otel"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
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
	ISS       = "iss"
	AUD       = "aud"
	JTI       = "jti"
)

const UnexpectedSigningMethod = "Unexpected signing method"
const JWKsAPIDef = "jwks_api_def_"

var (
	// List of common OAuth Client ID claims used by IDPs:
	oauthClientIDClaims = []string{
		"clientId",  // Keycloak
		"cid",       // OKTA
		"client_id", // Gluu
	}

	ErrNoSuitableUserIDClaimFound = errors.New("no suitable claims for user ID were found")
	ErrEmptyUserIDInSubClaim      = errors.New("found an empty user ID in sub claim")
	ErrEmptyUserIDInClaim         = errors.New("found an empty user ID in predefined base claim")
)

func (k *JWTMiddleware) Name() string {
	return "JWTMiddleware"
}

func (k *JWTMiddleware) Init() {
	config := k.Spec.APIDefinition

	if len(config.JWTJwksURIs) > 0 {
		// asynchronous fetches to not block API loading
		go func() {
			k.Logger().Debug("Pre-fetching JWKs asynchronously")
			// Drop the previous cache for the API ID
			k.Gw.deleteJWKCacheByAPIID(k.Spec.APIID)
			jwkCache := k.Gw.loadOrCreateJWKCacheByApiID(k.Spec.APIID)

			// Create client factory for JWK fetching
			clientFactory := NewExternalHTTPClientFactory(k.Gw)
			client, clientErr := clientFactory.CreateJWKClient()

			for _, jwk := range config.JWTJwksURIs {
				var jwkSet *jose.JSONWebKeySet
				var err error

				if clientErr == nil {
					jwkSet, err = getJWKWithClient(jwk.URL, client)
				}

				// Fallback to original method if factory fails
				if clientErr != nil || err != nil {
					jwkSet, err = GetJWK(jwk.URL, k.Gw.GetConfig().JWTSSLInsecureSkipVerify)
				}

				if err != nil {
					continue
				}

				jwkCache.Set(jwk.URL, jwkSet, jwk.GetCacheTimeoutSeconds(cache.DefaultExpiration))
			}
		}()
	}
}

func (k *JWTMiddleware) Unload() {
	// Unload method has been called asynchronously after Init is called
	// when a user changes the API configuration. Because of that behavior,
	// we only clean the cache if there is no spec found with the ID.
	// Init tries to clean the cache for the API ID when it starts
	spec := k.Gw.getApiSpec(k.Spec.APIID)
	if spec == nil {
		// delete the cache from the global map and stop its janitor.
		k.Gw.deleteJWKCacheByAPIID(k.Spec.APIID)
	}
}

func (k *JWTMiddleware) EnabledForSpec() bool {
	return k.Spec.EnableJWT
}

func (k *JWTMiddleware) loadOrCreateJWKCache() cache.Repository {
	return k.Gw.loadOrCreateJWKCacheByApiID(k.Spec.APIID)
}

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
	// Try to use HTTP client factory first
	clientFactory := NewExternalHTTPClientFactory(k.Gw)
	client, err := clientFactory.CreateJWKClient()
	if err != nil {
		// Fallback to original client
		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: k.Gw.GetConfig().JWTSSLInsecureSkipVerify},
			},
		}
	}

	var jwkSet JWKs
	jwkCache := k.loadOrCreateJWKCache()
	cachedJWK, found := jwkCache.Get("legacy-" + url)
	if !found {
		resp, err := client.Get(url)
		if err != nil {
			k.Gw.logJWKError(k.Logger(), url, err)
			return nil, err
		}
		defer resp.Body.Close()

		// Decode it
		if err := json.NewDecoder(resp.Body).Decode(&jwkSet); err != nil {
			k.Gw.logJWKError(k.Logger(), url, err)
			return nil, err
		}

		jwkCache.Set("legacy-"+url, jwkSet, cache.DefaultExpiration)
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
		found  bool
	)

	jwkCache := k.loadOrCreateJWKCache()
	cacheAPIDef := k.specCacheKey(k.Spec, JWKsAPIDef)
	cacheOutdated := false

	cachedAPIDefRaw, foundDef := jwkCache.Get(cacheAPIDef)
	if foundDef {
		cachedAPIDef, ok := cachedAPIDefRaw.(*apidef.APIDefinition)
		if !ok {
			cacheOutdated = true
		}

		decodedURL, err := base64.StdEncoding.DecodeString(cachedAPIDef.JWTSource)
		if err != nil {
			k.Logger().WithError(err).Errorf("JWKS source decode failed: %s is not a base64 string", cachedAPIDef.JWTSource)
			return nil, err
		}

		if string(decodedURL) != url {
			cacheOutdated = true
		} else {
			cachedJWK, ok := jwkCache.Get(url)
			if ok {
				found = true
				var okType bool
				jwkSet, okType = cachedJWK.(*jose.JSONWebKeySet)
				if !okType {
					// Invalidate cache if value is of unexpected type.
					// Value will be of unexpected type since it could also contain merged JWKs
					found = false
					jwkSet = nil
				}
			}
		}
	}

	if !found || cacheOutdated {
		// Try to use HTTP client factory first
		clientFactory := NewExternalHTTPClientFactory(k.Gw)
		client, clientErr := clientFactory.CreateJWKClient()
		if clientErr == nil {
			if jwkSet, err = getJWKWithClient(url, client); err != nil {
				k.Gw.logJWKError(k.Logger(), url, err)
				k.Logger().WithError(err).Info("Failed to decode JWKs body with factory client. Trying x5c PEM fallback.")
			}
		}

		// Fallback to original method if factory fails or JWK fetch fails
		if clientErr != nil || err != nil {
			if jwkSet, err = GetJWK(url, k.Gw.GetConfig().JWTSSLInsecureSkipVerify); err != nil {
				k.Gw.logJWKError(k.Logger(), url, err)
				k.Logger().Info("Failed to decode JWKs body. Trying x5c PEM fallback.")

				key, legacyError := k.legacyGetSecretFromURL(url, kid, keyType)
				if legacyError == nil {
					return key, nil
				}

				return nil, err
			}
		}

		// Cache it
		k.Logger().Debug("Caching JWK")
		jwkCache.Set(url, jwkSet, k.findCacheTimeoutByURL(url))
		jwkCache.Set(cacheAPIDef, k.Spec.APIDefinition, cache.DefaultExpiration)
	}

	k.Logger().Debug("Checking JWKs...")
	if keys := jwkSet.Key(kid); len(keys) > 0 {
		return keys[0].Key, nil
	}
	return nil, errors.New("No matching KID could be found")
}

func (k *JWTMiddleware) findCacheTimeoutByURL(url string) int64 {
	for _, uri := range k.Spec.JWTJwksURIs {
		if uri.URL == url {
			return uri.GetCacheTimeoutSeconds(cache.DefaultExpiration)
		}
	}
	return cache.DefaultExpiration
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

	// Try all JWK URIs, return on first successful match
	if len(config.JWTJwksURIs) > 0 && config.IsOAS {
		return k.getSecretFromMultipleJWKURIs(config.JWTJwksURIs, token.Header[KID], k.Spec.JWTSigningMethod)
	}

	// Check for central JWT source
	if config.JWTSource != "" {
		// Is it a URL?
		if httpScheme.MatchString(config.JWTSource) {
			return k.getSecretFromURL(config.JWTSource, token.Header[KID], k.Spec.JWTSigningMethod)
		}

		// If not, return the actual value
		decodedCert, err := base64.StdEncoding.DecodeString(config.JWTSource)
		if err != nil {
			k.Logger().WithError(err).Errorf("JWKS source decode failed: %s is not a base64 string", config.JWTSource)
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

var GetJWK = getJWK

func (k *JWTMiddleware) specCacheKey(spec *APISpec, prefix string) string {
	return prefix + spec.APIID + spec.OrgID
}

func (k *JWTMiddleware) collectCachedJWKsFromCache(jwkURIs []apidef.JWK) (jwkSets []*jose.JSONWebKeySet) {
	jwkCache := k.loadOrCreateJWKCache()
	for _, jwkURI := range jwkURIs {
		cachedItem, ok := jwkCache.Get(jwkURI.URL)
		if !ok {
			continue
		}
		jwkSet, ok := cachedItem.(*jose.JSONWebKeySet)
		if !ok {
			k.Logger().Warnf("Invalid JWK cache format for APIID %s, URL %s ? ignoring", k.Spec.APIID, jwkURI.URL)
		}
		jwkSets = append(jwkSets, jwkSet)
	}
	return jwkSets
}

func (k *JWTMiddleware) getSecretFromMultipleJWKURIs(jwkURIs []apidef.JWK, kidVal interface{}, keyType string) (interface{}, error) {
	if !k.Spec.APIDefinition.IsOAS {
		err := errors.New("this feature is only available when using OAS API")
		k.Logger().WithError(err).Infof("Failed to process api")

		return nil, err
	}

	var (
		jwkSets         []*jose.JSONWebKeySet
		fallbackJWKURIs []apidef.JWK
		kid, ok         = kidVal.(string)
	)

	if !ok {
		return nil, ErrKIDNotAString
	}

	cacheAPIDef := k.specCacheKey(k.Spec, JWKsAPIDef)
	cacheOutdated := false

	cachedAPIDefRaw, foundDef := k.loadOrCreateJWKCache().Get(cacheAPIDef)
	if foundDef {
		cachedAPIDef, ok := cachedAPIDefRaw.(*apidef.APIDefinition)
		if !ok {
			cacheOutdated = true
		}

		if jwkURLsChanged(cachedAPIDef.JWTJwksURIs, jwkURIs) {
			k.Logger().Infof("Detected change in JWK URLs ? refreshing cache for APIID %s", k.Spec.APIID)
			cacheOutdated = true
		} else {
			jwkSets = k.collectCachedJWKsFromCache(jwkURIs)
		}
	}

	if !foundDef || cacheOutdated || len(jwkSets) == 0 {
		jwkSets = nil
		jwkCache := k.loadOrCreateJWKCache()
		jwkCache.Flush()

		// Create client factory for JWK fetching
		clientFactory := NewExternalHTTPClientFactory(k.Gw)
		client, clientErr := clientFactory.CreateJWKClient()

		for _, jwk := range jwkURIs {
			var jwkSet *jose.JSONWebKeySet
			var err error

			// Try with factory client first
			if clientErr == nil {
				jwkSet, err = getJWKWithClient(jwk.URL, client)
			}

			// Fallback to original method if factory fails
			if clientErr != nil || err != nil {
				jwkSet, err = GetJWK(jwk.URL, k.Gw.GetConfig().JWTSSLInsecureSkipVerify)
			}

			if err != nil {
				k.Gw.logJWKError(k.Logger(), jwk.URL, err)
				fallbackJWKURIs = append(fallbackJWKURIs, jwk)
				continue
			}

			jwkCache.Set(jwk.URL, jwkSet, jwk.GetCacheTimeoutSeconds(cache.DefaultExpiration))
			jwkSets = append(jwkSets, jwkSet)
		}

		if len(jwkSets) > 0 {
			k.Logger().Debugf("Caching %d JWK sets for APIID %s", len(jwkSets), k.Spec.APIID)
			k.loadOrCreateJWKCache().Set(cacheAPIDef, k.Spec.APIDefinition, cache.DefaultExpiration)
		}
	}

	for _, jwkSet := range jwkSets {
		if keys := jwkSet.Key(kid); len(keys) > 0 {
			return keys[0].Key, nil
		}
	}

	for _, jwk := range fallbackJWKURIs {
		key, legacyErr := k.legacyGetSecretFromURL(jwk.URL, kid, keyType)
		if legacyErr == nil {
			return key, nil
		}
		k.Logger().WithError(legacyErr).Warnf("Legacy fallback failed for %s", jwk.URL)
	}

	err := errors.New("no matching KID found in any JWKs or fallback")
	k.Logger().WithError(err).Error("JWK resolution failed")

	return nil, err
}

func jwkURLsChanged(a, b []apidef.JWK) bool {
	if len(a) != len(b) {
		return true
	}

	urlMap := make(map[string]struct{}, len(b))
	for _, jwk := range b {
		urlMap[jwk.URL] = struct{}{}
	}

	for _, jwk := range a {
		if _, exists := urlMap[jwk.URL]; !exists {
			return true
		}
	}

	return false
}

func (k *JWTMiddleware) getPolicyIDFromToken(claims jwt.MapClaims) (string, bool) {
	if k.Spec.IsOAS {
		fieldNames := k.Spec.OAS.GetJWTConfiguration().BasePolicyClaims
		if len(fieldNames) == 0 && k.Spec.OAS.GetJWTConfiguration().PolicyFieldName != "" {
			fieldNames = append(fieldNames, k.Spec.OAS.GetJWTConfiguration().PolicyFieldName)
		}
		for _, claimField := range fieldNames {
			if policyID, found := getClaimValue(claims, claimField); found {
				k.Logger().Debugf("Found policy in claim: %s", claimField)
				return policyID, true
			}
		}

		k.Logger().Debugf("Could not identify a policy to apply to this token from fields: %v", fieldNames)
		return "", false
	} else {
		// Legacy path - also support nested claims
		if policyID, found := getClaimValue(claims, k.Spec.JWTPolicyFieldName); found {
			k.Logger().Debugf("Found policy in claim: %s", k.Spec.JWTPolicyFieldName)
			return policyID, true
		}

		k.Logger().Debugf("Could not identify a policy to apply to this token from field: %s", k.Spec.JWTPolicyFieldName)
		return "", false
	}
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
	if k.Spec.IsOAS {
		return k.getUserIDFromClaimOAS(claims)
	} else {
		return getUserIDFromClaim(claims, k.Spec.JWTIdentityBaseField, true)
	}
}

func (k *JWTMiddleware) getUserIDFromClaimOAS(claims jwt.MapClaims) (string, error) {
	identityBaseFields := k.Spec.OAS.GetJWTConfiguration().SubjectClaims
	if len(identityBaseFields) == 0 && k.Spec.OAS.GetJWTConfiguration().IdentityBaseField != "" {
		identityBaseFields = append(identityBaseFields, k.Spec.OAS.GetJWTConfiguration().IdentityBaseField)
	}
	checkedSub := false
	for _, identityBaseField := range identityBaseFields {
		if identityBaseField == SUB {
			checkedSub = true
		}

		id, err := getUserIDFromClaim(claims, identityBaseField, false)
		if err != nil {
			if errors.Is(ErrNoSuitableUserIDClaimFound, err) {
				continue
			}
			return "", err
		}
		return id, nil
	}
	// fallBack to Sub if SUB has not been checked yet
	if !checkedSub {
		return getUserIDFromClaim(claims, SUB, false)
	}
	return "", ErrNoSuitableUserIDClaimFound
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

// getClaimValue attempts to retrieve a string value from JWT claims using a two-step lookup:
// 1. First, it checks for a literal key (backward compatibility for keys with dots in their names)
// 2. If not found and the field contains a dot, it attempts nested lookup (e.g., "user.id" -> claims["user"]["id"])
//
// Returns the claim value and a boolean indicating if it was found.
func getClaimValue(claims jwt.MapClaims, claimField string) (string, bool) {
	// STEP 1: Try literal key first (backward compatibility)
	// Handles edge case where claim key contains literal dots (e.g., "user.id" as a key)
	if value, found := claims[claimField].(string); found && value != "" {
		return value, true
	}

	// STEP 2: Try nested lookup (new feature)
	// Only if literal key wasn't found AND the field contains a dot
	if strings.Contains(claimField, ".") {
		if value := nestedMapLookup(claims, strings.Split(claimField, ".")...); value != nil {
			if strValue, ok := value.(string); ok && strValue != "" {
				return strValue, true
			}
		}
	}

	return "", false
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
			// Only use default policies if configured - scope mapping may provide policies later
			if len(k.Spec.JWTDefaultPolicies) > 0 {
				isDefaultPol = true
				basePolicyID = k.Spec.JWTDefaultPolicies[0]
			}
		}

		// Only generate from policy if we have a base policy ID
		if basePolicyID != "" {
			session, err = k.Gw.generateSessionFromPolicy(basePolicyID,
				k.Spec.OrgID,
				true)

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
		} else {
			session = user.SessionState{OrgID: k.Spec.OrgID}
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
			if len(k.Spec.JWTDefaultPolicies) > 0 {
				isDefaultPol = true
				basePolicyID = k.Spec.JWTDefaultPolicies[0]
			}
		}
		// check if we received a valid policy ID in claim (skip if no base policy for scope-only auth)
		var policy user.Policy
		var ok bool
		if basePolicyID != "" {
			policy, ok = k.Gw.policies.PolicyByID(model.NewScopedCustomPolicyId(k.Spec.OrgID, basePolicyID))
			if !ok {
				k.reportLoginFailure(baseFieldData, r)
				k.Logger().Error("Policy ID found is invalid!")
				return errors.New("key not authorized: no matching policy"), http.StatusForbidden
			}
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

		if basePolicyID != "" && (!contains(pols, basePolicyID) || defaultPolicyListChanged) {
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
		if k.Spec.IsOAS {
			scopeClaimName = k.getScopeClaimNameOAS(claims)
		}
		if scopeClaimName == "" {
			scopeClaimName = "scope"
		}

		if scope := getScopeFromClaim(claims, scopeClaimName); len(scope) > 0 {
			// Start with base policy if it exists
			polIDs := []string{}
			if basePolicyID != "" {
				polIDs = []string{basePolicyID}
			}

			// If specified, scopes should not use default policy
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

		} else if basePolicyID == "" && exists {
			// Security: existing session with no scope in token and no base policy
			// Reject to prevent privilege escalation (token should reset policies)
			k.reportLoginFailure(baseFieldData, r)
			k.Logger().Error("Existing session requires scope or base policy when scope mapping is configured")
			return errors.New("key not authorized: no scope or policy in token"), http.StatusForbidden
		}
	}

	if basePolicyID == "" && len(k.Spec.JWTDefaultPolicies) == 0 {
		if len(session.PolicyIDs()) == 0 {
			k.reportLoginFailure(baseFieldData, r)
			k.Logger().Error("No policies could be determined from token (no base policy, no valid scopes)")
			return errors.New("key not authorized: no matching policy found"), http.StatusForbidden
		} else if exists && len(k.Spec.GetScopeToPolicyMapping()) == 0 {
			k.reportLoginFailure(baseFieldData, r)
			k.Logger().Error("Existing session requires policy in token when no defaults configured")
			return errors.New("key not authorized: no matching policy found"), http.StatusForbidden
		}
	}

	oauthClientID := ""
	// Get the OAuth client ID if available.
	// This step is skipped for external IDPs if IDPClientIDMappingDisabled is set to true.
	if !k.Spec.IDPClientIDMappingDisabled {
		k.Logger().Debug("IDP client ID mapping enabled, attempting to retrieve OAuth client ID from claims.")
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

			storageDriver := &storage.RedisCluster{KeyPrefix: prefix, HashKeys: false, ConnectionHandler: k.Gw.StorageConnectionHandler}
			storageDriver.Connect()

			k.Spec.OAuthManager = &OAuthManager{
				OsinServer: k.Gw.TykOsinNewServer(&osin.ServerConfig{},
					&RedisOsinStorageInterface{
						storageManager,
						k.Gw.GlobalSessionManager,
						storageDriver,
						k.Spec.OrgID,
						k.Gw,
					}),
			}
		}

		// Retrieve OAuth client data from storage and inject developer ID into the session object:
		client, err := k.Spec.OAuthManager.Storage().GetClient(oauthClientID)
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
			k.Logger().WithError(err).
				Warnf("Failed to retrieve OAuth client. For external IDPs, consider disabling IDP client ID mapping for better performance.")
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
		ctxSetSpanAttributes(r, k.Name(), otel.APIKeyAliasAttribute(session.Alias))
	}
	ctxSetJWTContextVars(k.Spec, r, token)

	return nil, http.StatusOK
}

func (k *JWTMiddleware) getScopeClaimNameOAS(claims jwt.MapClaims) string {
	claimNames := k.Spec.OAS.GetJWTConfiguration().Scopes.Claims
	if len(claimNames) == 0 && k.Spec.OAS.GetJWTConfiguration().Scopes.ClaimName != "" {
		claimNames = []string{k.Spec.OAS.GetJWTConfiguration().Scopes.ClaimName}
	}
	for _, claimName := range claimNames {
		for k := range claims {
			if k == claimName {
				return claimName
			}
		}
	}
	return ""
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
	ctxSetSpanAttributes(r, k.Name(), otel.APIKeyAliasAttribute(session.Alias))
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

		ctx.SetErrorClassification(r, tykerrors.ClassifyJWTError(tykerrors.ErrTypeAuthFieldMissing, k.Name()))
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
		if err := k.validateClaims(token); err != nil {
			ctx.SetErrorClassification(r, tykerrors.ClassifyJWTError(tykerrors.ErrTypeClaimsInvalid, k.Name()))
			return errors.New("Key not authorized: " + err.Error()), http.StatusUnauthorized
		}

		// Token is valid - let's move on

		// Are we mapping to a central JWT Secret?
		hasJWTSource := k.Spec.JWTSource != ""
		hasJwksURIs := len(k.Spec.JWTJwksURIs) > 0

		if hasJWTSource || hasJwksURIs {
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
			ctx.SetErrorClassification(r, tykerrors.ClassifyJWTError(tykerrors.ErrTypeUnexpectedSigningMethod, k.Name()))
			return errors.New(MsgKeyNotAuthorizedUnexpectedSigningMethod), http.StatusForbidden
		}
	}
	ctx.SetErrorClassification(r, tykerrors.ClassifyJWTError(tykerrors.ErrTypeTokenInvalid, k.Name()))
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

func (k *JWTMiddleware) validateClaims(token *jwt.Token) error {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return errors.New("invalid claims format")
	}
	if err := k.timeValidateJWTClaims(claims); err != nil {
		return err
	}

	// Extra OAS-specific validations
	if err := k.validateExtraClaims(claims, token); err != nil {
		return err
	}

	return nil
}

func validateIssuer(claims jwt.MapClaims, allowedIssuers []string) error {
	iss, exists := claims[ISS]
	if !exists {
		return errors.New("issuer claim is required but not present in token")
	}

	issuer, ok := iss.(string)
	if !ok {
		return errors.New("issuer claim must be a string")
	}

	for _, allowed := range allowedIssuers {
		if issuer == allowed {
			return nil
		}
	}

	return fmt.Errorf("invalid issuer claim: %s", issuer)
}

func validateAudience(claims jwt.MapClaims, allowedAudiences []string) error {
	aud, exists := claims[AUD]
	if !exists {
		return errors.New("audience claim is required but not present in token")
	}

	var audiences []string
	switch v := aud.(type) {
	case string:
		audiences = []string{v}
	case []interface{}:
		for _, a := range v {
			if s, ok := a.(string); ok {
				audiences = append(audiences, s)
			}
		}
	default:
		return errors.New("invalid audience claim format")
	}

	for _, tokenAud := range audiences {
		for _, allowedAud := range allowedAudiences {
			if tokenAud == allowedAud {
				return nil
			}
		}
	}

	return fmt.Errorf("no matching audience found in token: %v", audiences)
}

func validateJTI(claims jwt.MapClaims) error {
	if _, exists := claims[JTI]; !exists {
		return errors.New("JWT ID (jti) claim is required but not present in token")
	}
	return nil
}

func customClaimsContainsMatch(expectedValues []interface{}, claimValue interface{}) bool {
	matched := false
	for _, expectedValue := range expectedValues {
		switch cv := claimValue.(type) {
		case string:
			if expectedStr, ok := expectedValue.(string); ok {
				if strings.Contains(cv, expectedStr) {
					matched = true
					break
				}
			}
		case []interface{}:
			for _, item := range cv {
				if cmp.Equal(expectedValue, item) {
					matched = true
					break
				}
			}
		default:
			matched = cmp.Equal(expectedValue, cv)
		}
	}

	return matched
}

// validateCustomClaims performs validation of custom claims according to the configuration
func (k *JWTMiddleware) validateCustomClaimsNew(claims jwt.MapClaims) error {
	validationRules := k.Spec.OAS.GetJWTConfiguration().CustomClaimValidation
	claimsJson, err := json.Marshal(claims)
	if err != nil {
		return fmt.Errorf("error parsing claims: %w", err)
	}
	for claimsPath, validation := range validationRules {
		// validate json path
		_, err = jp.Parse([]byte(fmt.Sprintf("$.%s", claimsPath)))
		if err != nil {
			return fmt.Errorf("invalid claim path: %s", claimsPath)
		}

		result := gjson.Get(string(claimsJson), claimsPath)
		if !result.Exists() {
			if validation.NonBlocking {
				k.Logger().Warningf("Claim %s value does not match any expected values", claimsPath)
			} else {
				return fmt.Errorf("custom claim %s is required but not present in token", claimsPath)
			}
		}
		switch validation.Type {
		case oas.ClaimValidationTypeRequired:
			if result.Type == gjson.Null {
				if validation.NonBlocking {
					k.Logger().Warningf("Claim %s expects a non nil value", claimsPath)
				} else {
					return fmt.Errorf("custom claim %s expects a non nil value", claimsPath)
				}
			}
		case oas.ClaimValidationTypeContains:
			matched := customClaimsContainsMatch(validation.AllowedValues, result.Value())
			if !matched {
				if validation.NonBlocking {
					k.Logger().Warningf("Claim %s value does not contain any expected values", claimsPath)
					continue
				}
				return fmt.Errorf("claim %s value does not contain any expected values", claimsPath)
			}
		case oas.ClaimValidationTypeExactMatch:
			matched := false
			for _, expectedValue := range validation.AllowedValues {
				if cmp.Equal(result.Value(), expectedValue) {
					matched = true
					break
				}
			}
			if !matched {
				if validation.NonBlocking {
					k.Logger().Warningf("Claim %s value does not match any expected values", claimsPath)
					continue
				}
				return fmt.Errorf("claim %s value does not match any expected values", claimsPath)
			}
		}
	}
	return nil
}

func validateSubjectValue(subject string, allowedSubjects []string) error {
	for _, allowed := range allowedSubjects {
		if subject == allowed {
			return nil
		}
	}
	return fmt.Errorf("invalid subject value: %s", subject)
}

func (k *JWTMiddleware) validateExtraClaims(claims jwt.MapClaims, token *jwt.Token) error {
	if !k.Spec.IsOAS {
		return nil // Skip extra validations for non-OAS APIs
	}

	jwtConfig := k.Spec.OAS.GetJWTConfiguration()

	// Issuer validation
	if len(jwtConfig.AllowedIssuers) > 0 {
		if err := validateIssuer(claims, jwtConfig.AllowedIssuers); err != nil {
			k.Logger().WithError(err).Error("JWT issuer validation failed")
			return err
		}
	}

	// Audience validation
	if len(jwtConfig.AllowedAudiences) > 0 {
		if err := validateAudience(claims, jwtConfig.AllowedAudiences); err != nil {
			k.Logger().WithError(err).Error("JWT audience validation failed")
			return err
		}
	}

	// JWT ID validation
	if jwtConfig.JTIValidation.Enabled {
		if err := validateJTI(claims); err != nil {
			k.Logger().WithError(err).Error("JWT ID validation failed")
			return err
		}
	}

	// Subject validation
	if len(jwtConfig.AllowedSubjects) > 0 {
		subject, err := k.getIdentityFromToken(token)
		if err != nil {
			k.Logger().WithError(err).Error("Failed to get identity from token")
			return err
		}

		if err := validateSubjectValue(subject, jwtConfig.AllowedSubjects); err != nil {
			k.Logger().WithError(err).Error("JWT subject validation failed")
			return err
		}
	}

	// Custom claims validation
	if len(jwtConfig.CustomClaimValidation) > 0 {
		if err := k.validateCustomClaimsNew(claims); err != nil {
			k.Logger().WithError(err).Error("JWT custom claims validation failed")
			return err
		}
	}

	return nil
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
	var polId model.PolicyID

	if enforceOrg {
		polId = model.NewScopedCustomPolicyId(orgID, policyID)
	} else {
		polId = model.NonScopedLastInsertedPolicyId(policyID)
	}

	policy, ok := gw.policies.PolicyByID(polId)
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
	// Supports both RSA + RSAPSS Signing.
	case RSASign:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			if _, ok := token.Method.(*jwt.SigningMethodRSAPSS); !ok {
				return fmt.Errorf("%v: %v and not RSA or RSAPSS signature", UnexpectedSigningMethod, token.Header["alg"])
			}
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
			TLSClientConfig: &tls.Config{InsecureSkipVerify: jwtSSLInsecureSkipVerify},
		},
	}

	return getJWKWithClient(url, &client)
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
func getUserIDFromClaim(claims jwt.MapClaims, identityBaseField string, shouldFallback bool) (string, error) {
	if identityBaseField != "" {
		if userID, found := getClaimValue(claims, identityBaseField); found {
			log.WithField("userId", userID).Debug("Found User Id in Base Field")
			return userID, nil
		}

		// Check if the field exists but is empty
		if value, exists := claims[identityBaseField]; exists {
			if strValue, ok := value.(string); ok && strValue == "" {
				err := fmt.Errorf("%w, claim: %s", ErrEmptyUserIDInClaim, identityBaseField)
				log.Error(err)
				return "", err
			}
		}

		// Also check nested path for empty string
		if strings.Contains(identityBaseField, ".") {
			if value := nestedMapLookup(claims, strings.Split(identityBaseField, ".")...); value != nil {
				if strValue, ok := value.(string); ok && strValue == "" {
					err := fmt.Errorf("%w, claim: %s", ErrEmptyUserIDInClaim, identityBaseField)
					log.Error(err)
					return "", err
				}
			}
		}

		log.WithField("Base Field", identityBaseField).Warning("Base Field claim not found, trying to find user ID in 'sub' claim.")
	}

	if shouldFallback {
		if userID, found := claims[SUB].(string); found {
			if len(userID) > 0 {
				log.WithField("userId", userID).Debug("Found User Id in 'sub' claim")
				return userID, nil
			}

			log.Error(ErrEmptyUserIDInSubClaim)
			return "", ErrEmptyUserIDInSubClaim
		}
	}

	log.Error(ErrNoSuitableUserIDClaimFound)
	return "", ErrNoSuitableUserIDClaimFound
}

func (gw *Gateway) invalidateJWKSCacheByAPIID(apiID string) {
	gw.deleteJWKCacheByAPIID(apiID)
	mainLog.Debugf("JWKS cache for API: %s has been invalidated", apiID)
}

func (gw *Gateway) invalidateJWKSCacheForAPIID(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]
	gw.invalidateJWKSCacheByAPIID(apiID)
	// Cache invalidation is idempotent: calling it ensures the key is absent,
	// regardless of whether it was cached before or not.
	doJSONWrite(w, http.StatusOK, apiOk("cache invalidated"))
}

func (gw *Gateway) invalidateJWKSCacheForAllAPIs(w http.ResponseWriter, _ *http.Request) {
	gw.apiJWKCaches.Range(func(key, _ any) bool {
		apiID, ok := key.(string)
		if ok {
			gw.deleteJWKCacheByAPIID(apiID)
		}
		return true
	})

	doJSONWrite(w, http.StatusOK, apiOk("cache invalidated"))
}

func (gw *Gateway) loadOrCreateJWKCacheByApiID(apiID string) cache.Repository {
	if raw, ok := gw.apiJWKCaches.Load(apiID); ok {
		if jwkCache, ok := raw.(cache.Repository); ok {
			return jwkCache
		}
	}

	newCache := buildJWKSCache(gw.GetConfig())
	raw, loaded := gw.apiJWKCaches.LoadOrStore(apiID, newCache)

	// If another goroutine won the race, close the unused cache
	if loaded {
		newCache.Close()
	}

	jwkCache, ok := raw.(cache.Repository)
	if !ok {
		panic("JWKCache instance must implement cache.Repository")
	}

	return jwkCache
}

func (gw *Gateway) deleteJWKCacheByAPIID(apiID string) {
	if existing, ok := gw.apiJWKCaches.LoadAndDelete(apiID); ok {
		if repo, ok := existing.(cache.Repository); ok {
			repo.Close()
		}
	}
}

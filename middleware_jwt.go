package main

import "net/http"

import (
	"crypto/md5"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/TykTechnologies/tykcommon"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
	"github.com/pmylund/go-cache"
)

// KeyExists will check if the key being used to access the API is in the request data,
// and then if the key is in the storage engine
type JWTMiddleware struct {
	*TykMiddleware
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

func (a *JWTMiddleware) IsEnabledForSpec() bool {
	return true
}

func (k *JWTMiddleware) copyResponse(dst io.Writer, src io.Reader) {
	io.Copy(dst, src)
}

func (k *JWTMiddleware) getSecretFromURL(url string, kid string, keyType string) ([]byte, error) {
	// Implement a cache
	if JWKCache == nil {
		log.Debug("Creating JWK Cache")
		JWKCache = cache.New(240*time.Second, 30*time.Second)
	}

	var thisJWKSet JWKs
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

		decErr := json.Unmarshal(contents, &thisJWKSet)
		if decErr != nil {
			log.Error("Failed to decode body JWK: ", decErr)
			return nil, err
		}

		// Cache it
		log.Debug("Caching JWK")
		JWKCache.Set(k.TykMiddleware.Spec.APIID, thisJWKSet, cache.DefaultExpiration)
	} else {
		thisJWKSet = cachedJWK.(JWKs)
	}

	log.Debug("Checking JWKs...")
	for _, val := range thisJWKSet.Keys {
		if val.KID == kid {
			if strings.ToLower(val.Kty) == strings.ToLower(keyType) {
				if len(val.X5c) > 0 {
					// Use the first cert only
					decodedCert, decErr := b64.StdEncoding.DecodeString(val.X5c[0])
					if decErr != nil {
						return nil, decErr
					}
					log.Debug("Found cert! Replying...")
					log.Debug("Cert was: ", string(decodedCert))
					return decodedCert, nil
				}
				return nil, errors.New("No certificates in JWK!")
			}
		}
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
	thisConfig := k.TykMiddleware.Spec.APIDefinition
	// Check for central JWT source
	if thisConfig.JWTSource != "" {

		// Is it a URL?
		if strings.HasPrefix(strings.ToLower(thisConfig.JWTSource), "http://") || strings.HasPrefix(strings.ToLower(thisConfig.JWTSource), "https://") {
			secret, urlErr := k.getSecretFromURL(thisConfig.JWTSource, token.Header["kid"].(string), k.TykMiddleware.Spec.JWTSigningMethod)
			if urlErr != nil {
				return nil, urlErr
			}

			return secret, nil
		}

		// If not, return the actual value
		decodedCert, decErr := b64.StdEncoding.DecodeString(thisConfig.JWTSource)
		if decErr != nil {
			return nil, decErr
		}
		return decodedCert, nil
	}

	// Try using a kid or sub header
	tykId, found := k.getIdentityFomToken(token)

	if !found {
		return nil, errors.New("Key ID not found")
	}

	var thisSessionState SessionState
	var rawKeyExists bool

	// Couldn't b64 decode the kid, so lets try it raw
	log.Debug("Getting key: ", tykId)
	thisSessionState, rawKeyExists = k.TykMiddleware.CheckSessionAndIdentityForValidKey(tykId)
	if !rawKeyExists {
		log.Info("Not found!")
		return nil, errors.New("Token invalid, key not found.")
	}
	return []byte(thisSessionState.JWTData.Secret), nil
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
		clientsessionState, keyExists := k.TykMiddleware.CheckSessionAndIdentityForValidKey(clientID)
		if !keyExists {
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
	var baseFound bool
	var baseFieldData string
	var tokenID string
	baseFieldData, baseFound = token.Claims.(jwt.MapClaims)[k.TykMiddleware.Spec.APIDefinition.JWTIdentityBaseField].(string)
	if !baseFound {
		var found bool
		log.Warning("Base Field not found, using SUB")
		baseFieldData, found = token.Claims.(jwt.MapClaims)["sub"].(string)
		if !found {
			log.Error("ID Could not be generated. Failing Request.")
			k.reportLoginFailure("[NOT FOUND]", r)
			return errors.New("Key not authorized"), 403
		}

	}
	log.Debug("Base Field ID set to: ", baseFieldData)
	data := []byte(baseFieldData)
	tokenID = fmt.Sprintf("%x", md5.Sum(data))
	SessionID := k.TykMiddleware.Spec.OrgID + tokenID

	log.Debug("JWT Temporary session ID is: ", SessionID)

	thisSessionState, keyExists := k.TykMiddleware.CheckSessionAndIdentityForValidKey(SessionID)
	if !keyExists {
		// Create it
		log.Debug("Key does not exist, creating")
		thisSessionState = SessionState{}

		// We need a base policy as a template, either get it from the token itself OR a proxy client ID within Tyk
		basePolicyID, foundPolicy := k.getBasePolicyID(token)
		if !foundPolicy {
			return errors.New("Key not authorized: no matching policy found"), 403
		}

		newSessionState, err := generateSessionFromPolicy(basePolicyID,
			k.TykMiddleware.Spec.APIDefinition.OrgID,
			true)

		if err == nil {
			thisSessionState = newSessionState
			thisSessionState.MetaData = map[string]interface{}{"TykJWTSessionID": SessionID}
			thisSessionState.Alias = baseFieldData

			// Update the session in the session manager in case it gets called again
			k.Spec.SessionManager.UpdateSession(SessionID, thisSessionState, GetLifetime(k.Spec, &thisSessionState))
			log.Debug("Policy applied to key")

			if (k.TykMiddleware.Spec.BaseIdentityProvidedBy == tykcommon.JWTClaim) || (k.TykMiddleware.Spec.BaseIdentityProvidedBy == tykcommon.UnsetAuth) {
				context.Set(r, SessionData, thisSessionState)
				context.Set(r, AuthHeaderValue, SessionID)
			}
			k.setContextVars(r, token)
			return nil, 200
		}

		k.reportLoginFailure(baseFieldData, r)
		log.Error("Could not find a valid policy to apply to this token!")
		return errors.New("Key not authorized: no matching policy"), 403
	}

	log.Debug("Key found")
	if (k.TykMiddleware.Spec.BaseIdentityProvidedBy == tykcommon.JWTClaim) || (k.TykMiddleware.Spec.BaseIdentityProvidedBy == tykcommon.UnsetAuth) {
		context.Set(r, SessionData, thisSessionState)
		context.Set(r, AuthHeaderValue, SessionID)
	}
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
	thisSessionState, keyExists := k.TykMiddleware.CheckSessionAndIdentityForValidKey(tykId)
	if !keyExists {
		k.reportLoginFailure(tykId, r)
		return errors.New("Key not authorized"), 403
	}

	log.Debug("Raw key ID found.")
	context.Set(r, SessionData, thisSessionState)
	context.Set(r, AuthHeaderValue, tykId)
	k.setContextVars(r, token)
	return nil, 200
}

func (k *JWTMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	thisConfig := k.TykMiddleware.Spec.APIDefinition.Auth
	var tykId string

	// Get the token
	rawJWT := r.Header.Get(thisConfig.AuthHeaderName)
	if thisConfig.UseParam {
		tempRes := CopyRequest(r)

		// Set hte header name
		rawJWT = tempRes.FormValue(thisConfig.AuthHeaderName)
	}

	if thisConfig.UseCookie {
		tempRes := CopyRequest(r)
		authCookie, notFoundErr := tempRes.Cookie(thisConfig.AuthHeaderName)
		if notFoundErr != nil {
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

		log.Debug("Looked in: ", thisConfig.AuthHeaderName)
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
		if k.TykMiddleware.Spec.JWTSigningMethod == "hmac" {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
		} else if k.TykMiddleware.Spec.JWTSigningMethod == "rsa" {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
		} else if k.TykMiddleware.Spec.JWTSigningMethod == "ecdsa" {
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
		} else {
			log.Warning("No signing method found in API Definition, defaulting to HMAC")
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
		}

		var val []byte
		var secretErr error

		val, secretErr = k.getSecret(token)
		if secretErr != nil {
			log.Error("Couldn't get token: ", secretErr)
		}

		if k.TykMiddleware.Spec.JWTSigningMethod == "rsa" {
			asRSA, err := jwt.ParseRSAPublicKeyFromPEM(val)
			if err != nil {
				log.Error("Failed to deccode JWT to RSA type")
				return nil, err
			}
			return asRSA, secretErr
		}

		return val, secretErr
	})

	if err == nil && token.Valid {
		// Token is valid - let's move on

		// Are we mapping to a central JWT Secret?
		if k.TykMiddleware.Spec.APIDefinition.JWTSource != "" {
			return k.processCentralisedJWT(w, r, token)
		}

		// No, let's try one-to-one mapping
		return k.processOneToOneTokenMap(w, r, token)

	} else {
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
}

func (k *JWTMiddleware) setContextVars(r *http.Request, token *jwt.Token) {
	// Flatten claims and add to context
	if k.Spec.EnableContextVars {
		cnt, contextFound := context.GetOk(r, ContextData)
		var contextDataObject map[string]interface{}
		if contextFound {
			contextDataObject = cnt.(map[string]interface{})
			claimPrefix := "jwt_claims_"

			for claimName, claimValue := range token.Claims.(jwt.MapClaims) {
				thisClaim := claimPrefix + claimName
				contextDataObject[thisClaim] = claimValue
			}

			// Key data
			authHeaderValue := context.Get(r, AuthHeaderValue)
			contextDataObject["token"] = authHeaderValue

			context.Set(r, ContextData, contextDataObject)
		}

	}
}

func generateSessionFromPolicy(policyID string, OrgID string, enforceOrg bool) (SessionState, error) {
	log.Debug("Generating from policyID: ", policyID)
	log.Debug(Policies)
	policy, ok := Policies[policyID]
	thisSessionState := SessionState{}
	log.Debug(ok)
	if ok {
		log.Debug("Policy found")
		// Check ownership, policy org owner must be the same as API,
		// otherwise youcould overwrite a session key with a policy from a different org!

		if enforceOrg {
			if policy.OrgID != OrgID {
				log.Error("Attempting to apply policy from different organisation to key, skipping")
				return thisSessionState, errors.New("Key not authorized: no matching policy")
			}
		} else {
			// Org isn;t enforced, so lets use the policy baseline
			OrgID = policy.OrgID
		}

		log.Debug("Found policy, applying")
		thisSessionState.ApplyPolicyID = policyID
		thisSessionState.OrgID = OrgID
		thisSessionState.Allowance = policy.Rate // This is a legacy thing, merely to make sure output is consistent. Needs to be purged
		thisSessionState.Rate = policy.Rate
		thisSessionState.Per = policy.Per
		thisSessionState.QuotaMax = policy.QuotaMax
		thisSessionState.QuotaRenewalRate = policy.QuotaRenewalRate
		thisSessionState.AccessRights = policy.AccessRights
		thisSessionState.HMACEnabled = policy.HMACEnabled
		thisSessionState.IsInactive = policy.IsInactive
		thisSessionState.Tags = policy.Tags

		if policy.KeyExpiresIn > 0 {
			thisSessionState.Expires = time.Now().Unix() + policy.KeyExpiresIn
		}

		return thisSessionState, nil
	}

	return thisSessionState, errors.New("Policy not found")
}

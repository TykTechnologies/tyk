package gateway

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/pmylund/go-cache"
	"github.com/square/go-jose"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

var (
	errParseJWK = errors.New("parse JWK failed")
)

type JWTBase struct {
	BaseMiddleware
}

func (j *JWTBase) getJWKKeySetFromURL(url string) (*jose.JSONWebKeySet, error) {
	// Implement a cache
	if JWKCache == nil {
		j.logger.Debug("Creating JWK Cache")
		JWKCache = cache.New(240*time.Second, 30*time.Second)
	}

	var jwkSet *jose.JSONWebKeySet
	var client http.Client
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: j.Gw.GetConfig().JWTSSLInsecureSkipVerify},
	}

	// Get the JWK
	j.logger.Debug("Pulling JWK")
	resp, err := client.Get(url)
	if err != nil {
		j.logger.WithError(err).Error("Failed to get resource URL")
		return nil, err
	}
	defer resp.Body.Close()
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		j.logger.WithError(err).Error("Failed to get read response body")
		return nil, err
	}

	if jwkSet, err = parseJWK(buf); err != nil {
		return nil, errParseJWK
	}

	return jwkSet, nil
}

func (j *JWTBase) legacyGetSecretFromURL(url, kid, keyType string) (interface{}, error) {
	// Implement a cache
	if JWKCache == nil {
		JWKCache = cache.New(240*time.Second, 30*time.Second)
	}

	var client http.Client
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: j.Gw.GetConfig().JWTSSLInsecureSkipVerify},
	}

	var jwkSet JWKs
	cachedJWK, found := JWKCache.Get("legacy-" + j.Spec.APIID)
	if !found {
		resp, err := client.Get(url)
		if err != nil {
			j.Logger().WithError(err).Error("Failed to get resource URL")
			return nil, err
		}
		defer resp.Body.Close()

		// Decode it
		if err := json.NewDecoder(resp.Body).Decode(&jwkSet); err != nil {
			j.Logger().WithError(err).Error("Failed to decode body JWK")
			return nil, err
		}

		JWKCache.Set("legacy-"+j.Spec.APIID, jwkSet, cache.DefaultExpiration)
	} else {
		jwkSet = cachedJWK.(JWKs)
	}

	for _, val := range jwkSet.Keys {
		if val.KID != kid || !strings.EqualFold(val.Kty, keyType) {
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

func (j *JWTBase) getSecretFromURL(url, kid, keyType string, checkLegacy bool) (interface{}, error) {
	// Implement a cache
	if JWKCache == nil {
		j.Logger().Debug("Creating JWK Cache")
		JWKCache = cache.New(240*time.Second, 30*time.Second)
	}

	var jwkSet *jose.JSONWebKeySet
	var client http.Client
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: j.Gw.GetConfig().JWTSSLInsecureSkipVerify},
	}

	cachedJWK, found := JWKCache.Get(j.Spec.APIID)
	if !found {
		var err error
		jwkSet, err = j.getJWKKeySetFromURL(url)

		if err != nil {
			j.Logger().WithError(err).Info("Failed to decode JWKs body. ")
			if checkLegacy {
				j.logger.Info("Trying x5c PEM fallback.")
				key, legacyError := j.legacyGetSecretFromURL(url, kid, keyType)
				if legacyError == nil {
					return key, nil
				}
			}

			return nil, err
		}

		// Cache it
		j.Logger().Debug("Caching JWK")
		JWKCache.Set(j.BaseMiddleware.Spec.APIID, jwkSet, cache.DefaultExpiration)
	} else {
		jwkSet = cachedJWK.(*jose.JSONWebKeySet)
	}

	j.Logger().Debug("Checking JWKs...")
	if keys := jwkSet.Key(kid); len(keys) > 0 {
		return keys[0].Key, nil
	}
	return nil, errors.New("No matching KID could be found")
}

func (j *JWTBase) getSecretFromURLOrConfig(token *jwt.Token, keyType string, checkLegacy bool) (interface{}, error) {
	// Is it a URL?
	if httpScheme.MatchString(j.Spec.JWTSource) {
		return j.getSecretFromURL(j.Spec.JWTSource, token.Header[KID].(string), keyType, checkLegacy)
	}

	// If not, return the actual value
	decodedCert, err := base64.StdEncoding.DecodeString(j.Spec.JWTSource)
	if err != nil {
		return nil, err
	}

	// Is decoded url too?
	if httpScheme.MatchString(string(decodedCert)) {
		secret, err := j.getSecretFromURL(string(decodedCert), token.Header[KID].(string), keyType, checkLegacy)
		if err != nil {
			return nil, err
		}

		return secret, nil
	}

	return decodedCert, nil // Returns the decoded secret
}

func (j *JWTBase) timeValidateJWTClaims(c jwt.MapClaims) *jwt.ValidationError {
	vErr := new(jwt.ValidationError)
	now := time.Now().Unix()
	// The claims below are optional, by default, so if they are set to the
	// default value in Go, let's not fail the verification for them.
	if !c.VerifyExpiresAt(now-int64(j.Spec.JWTExpiresAtValidationSkew), false) {
		vErr.Inner = errors.New("token has expired")
		vErr.Errors |= jwt.ValidationErrorExpired
	}

	if !c.VerifyIssuedAt(now+int64(j.Spec.JWTIssuedAtValidationSkew), false) {
		vErr.Inner = errors.New("token used before issued")
		vErr.Errors |= jwt.ValidationErrorIssuedAt
	}

	if !c.VerifyNotBefore(now+int64(j.Spec.JWTNotBeforeValidationSkew), false) {
		vErr.Inner = errors.New("token is not valid yet")
		vErr.Errors |= jwt.ValidationErrorNotValidYet
	}

	if vErr.Errors == 0 {
		return nil
	}

	return vErr
}

func (j *JWTBase) getUserIdFromClaim(claims jwt.MapClaims) (string, error) {
	var (
		userId string
		found  bool
	)

	if j.Spec.JWTIdentityBaseField != "" {
		if userId, found = claims[j.Spec.JWTIdentityBaseField].(string); found {
			if len(userId) > 0 {
				j.Logger().WithField("userId", userId).Debug("Found User Id in Base Field")
				return userId, nil
			}
			message := "found an empty user ID in predefined base field claim " + j.Spec.JWTIdentityBaseField
			j.Logger().Error(message)
			return "", errors.New(message)
		}

		if !found {
			j.Logger().WithField("Base Field", j.Spec.JWTIdentityBaseField).Warning("Base Field claim not found, trying to find user ID in 'sub' claim.")
		}
	}

	if userId, found = claims[SUB].(string); found {
		if len(userId) > 0 {
			j.Logger().WithField("userId", userId).Debug("Found User Id in 'sub' claim")
			return userId, nil
		}
		message := "found an empty user ID in sub claim"
		j.Logger().Error(message)
		return "", errors.New(message)
	}

	message := "no suitable claims for user ID were found"
	j.Logger().Error(message)
	return "", errors.New(message)
}

func (j *JWTBase) getIdentityFromToken(token *jwt.Token) (string, error) {
	// Check which claim is used for the id - kid or sub header
	// If is not supposed to ignore KID - will use this as ID if not empty
	if !j.Spec.APIDefinition.JWTSkipKid {
		if tykId, idFound := token.Header[KID].(string); idFound {
			j.Logger().Debug("Found: ", tykId)
			return tykId, nil
		}
	}
	// In case KID was empty or was set to ignore KID ==> Will try to get the Id from JWTIdentityBaseField or fallback to 'sub'
	tykId, err := j.getUserIdFromClaim(token.Claims.(jwt.MapClaims))
	return tykId, err
}

func (j *JWTBase) getSecretToVerifySignature(r *http.Request, token *jwt.Token, verifySessionIdentity bool) (interface{}, error) {
	config := j.Spec.APIDefinition
	// Check for central JWT source
	if config.JWTSource != "" {
		return j.getSecretFromURLOrConfig(token, j.Spec.JWTSigningMethod, verifySessionIdentity)
	}

	// If we are here, there's no central JWT source
	if verifySessionIdentity {
		// Get the ID from the token (in KID header or configured claim or SUB claim)
		tykId, err := j.getIdentityFromToken(token)
		if err != nil {
			return nil, err
		}

		// Couldn't base64 decode the kid, so lets try it raw
		j.Logger().Debug("Getting key: ", tykId)
		session, rawKeyExists := j.CheckSessionAndIdentityForValidKey(tykId, r)
		if !rawKeyExists {
			return nil, errors.New("token invalid, key not found")
		}
		return []byte(session.JWTData.Secret), nil
	}

	return nil, errors.New("couldn't verify signature")
}

func (j *JWTBase) ParseJWTHook(r *http.Request, verifySessionIdentity bool) func(token *jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		switch j.Spec.JWTSigningMethod {
		case HMACSign:
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("%v: %v and not HMAC signature", UnexpectedSigningMethod, token.Header["alg"])
			}
		case RSASign:
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("%v: %v and not RSA signature", UnexpectedSigningMethod, token.Header["alg"])
			}
		case ECDSASign:
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("%v: %v and not ECDSA signature", UnexpectedSigningMethod, token.Header["alg"])
			}
		default:
			j.logger.Warning("No signing method found in API Definition, defaulting to HMAC signature")
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("%v: %v", UnexpectedSigningMethod, token.Header["alg"])
			}
		}

		val, err := j.getSecretToVerifySignature(r, token, verifySessionIdentity)
		if err != nil {
			j.Logger().WithError(err).Error("Couldn't get token")
			return nil, err
		}

		switch j.Spec.JWTSigningMethod {
		case RSASign, ECDSASign:
			switch e := val.(type) {
			case []byte:
				key, err := ParseRSAPublicKey(e)
				if err != nil {
					j.logger.WithError(err).Error("Failed to decode JWT key")
					return nil, errors.New("Failed to decode JWT key")
				}
				return key, nil
			default:
				// We have already parsed the correct key so we just return it here.No need
				// for checks because they already happened somewhere ele.
				return e, nil
			}

		default:
			return val, nil
		}
	}
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

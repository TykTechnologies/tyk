package main

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/pmylund/go-cache"
	"golang.org/x/crypto/bcrypt"

	"github.com/TykTechnologies/murmur3"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"
)

const defaultBasicAuthTTL = time.Duration(60) * time.Second

// BasicAuthKeyIsValid uses a username instead of
type BasicAuthKeyIsValid struct {
	BaseMiddleware
	cache *cache.Cache
}

func (k *BasicAuthKeyIsValid) Name() string {
	return "BasicAuthKeyIsValid"
}

// EnabledForSpec checks if UseBasicAuth is set in the API definition.
func (k *BasicAuthKeyIsValid) EnabledForSpec() bool {
	return k.Spec.UseBasicAuth
}

// requestForBasicAuth sends error code and message along with WWW-Authenticate header to client.
func (k *BasicAuthKeyIsValid) requestForBasicAuth(w http.ResponseWriter, msg string) (error, int) {
	authReply := "Basic realm=\"" + k.Spec.Name + "\""

	w.Header().Add("WWW-Authenticate", authReply)
	return errors.New(msg), http.StatusUnauthorized
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (k *BasicAuthKeyIsValid) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	token := r.Header.Get("Authorization")
	logEntry := getLogEntryForRequest(r, token, nil)
	if token == "" {
		// No header value, fail
		logEntry.Info("Attempted access with malformed header, no auth header found.")

		return k.requestForBasicAuth(w, "Authorization field missing")
	}

	bits := strings.Split(token, " ")
	if len(bits) != 2 {
		// Header malformed
		logEntry.Info("Attempted access with malformed header, header not in basic auth format.")

		return errors.New("Attempted access with malformed header, header not in basic auth format"), http.StatusBadRequest
	}

	// Decode the username:password string
	authvaluesStr, err := base64.StdEncoding.DecodeString(bits[1])
	if err != nil {
		logEntry.Info("Base64 Decoding failed of basic auth data: ", err)

		return errors.New("Attempted access with malformed header, auth data not encoded correctly"), http.StatusBadRequest
	}

	authValues := strings.Split(string(authvaluesStr), ":")
	if len(authValues) != 2 {
		// Header malformed
		logEntry.Info("Attempted access with malformed header, values not in basic auth format.")

		return errors.New("Attempted access with malformed header, values not in basic auth format"), http.StatusBadRequest
	}

	// Check if API key valid
	keyName := generateToken(k.Spec.OrgID, authValues[0])
	logEntry = getLogEntryForRequest(r, keyName, nil)
	session, keyExists := k.CheckSessionAndIdentityForValidKey(keyName, r)
	if !keyExists {
		logEntry.Info("Attempted access with non-existent user.")

		return k.handleAuthFail(w, r, token)
	}

	switch session.BasicAuthData.Hash {
	case user.HashBCrypt:

		if err := k.compareHashAndPassword(session.BasicAuthData.Password, authValues[1], logEntry); err != nil {
			logEntry.Warn("Attempted access with existing user, failed password check.")
			return k.handleAuthFail(w, r, token)
		}
	case user.HashPlainText:
		if session.BasicAuthData.Password != authValues[1] {

			logEntry.Warn("Attempted access with existing user, failed password check.")
			return k.handleAuthFail(w, r, token)
		}
	}

	// Set session state on context, we will need it later
	switch k.Spec.BaseIdentityProvidedBy {
	case apidef.BasicAuthUser, apidef.UnsetAuth:
		ctxSetSession(r, &session, keyName, false)
	}

	return nil, http.StatusOK
}

func (k *BasicAuthKeyIsValid) handleAuthFail(w http.ResponseWriter, r *http.Request, token string) (error, int) {

	// Fire Authfailed Event
	AuthFailed(k, r, token)

	// Report in health check
	reportHealthValue(k.Spec, KeyFailure, "-1")

	return k.requestForBasicAuth(w, "User not authorised")
}

func (k *BasicAuthKeyIsValid) doBcryptWithCache(cacheDuration time.Duration, hashedPassword []byte, password []byte) error {
	if err := bcrypt.CompareHashAndPassword(hashedPassword, password); err != nil {

		return err
	}

	hasher := murmur3.New32()
	hasher.Write(password)
	k.cache.Set(string(hashedPassword), string(hasher.Sum(nil)), cacheDuration)

	return nil
}

func (k *BasicAuthKeyIsValid) compareHashAndPassword(hash string, password string, logEntry *logrus.Entry) error {

	cacheEnabled := !k.Spec.BasicAuth.DisableCaching
	passwordBytes := []byte(password)
	hashBytes := []byte(hash)

	if !cacheEnabled {

		logEntry.Debug("cache disabled")
		return bcrypt.CompareHashAndPassword(hashBytes, passwordBytes)
	}

	cacheTTL := defaultBasicAuthTTL // set a default TTL, then override based on BasicAuth.CacheTTL
	if k.Spec.BasicAuth.CacheTTL > 0 {
		cacheTTL = time.Duration(k.Spec.BasicAuth.CacheTTL) * time.Second
	}

	cachedPass, inCache := k.cache.Get(hash)
	if !inCache {

		logEntry.Debug("cache enabled: miss: bcrypt")
		return k.doBcryptWithCache(cacheTTL, hashBytes, passwordBytes)
	}

	hasher := murmur3.New32()
	hasher.Write(passwordBytes)
	if cachedPass.(string) != string(hasher.Sum(nil)) {

		logEntry.Warn("cache enabled: hit: failed auth: bcrypt")
		return bcrypt.CompareHashAndPassword(hashBytes, passwordBytes)
	}

	logEntry.Debug("cache enabled: hit: success")
	return nil
}

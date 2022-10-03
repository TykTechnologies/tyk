package gateway

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	cache "github.com/pmylund/go-cache"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sync/singleflight"

	"github.com/TykTechnologies/murmur3"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/regexp"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

const defaultBasicAuthTTL = time.Duration(60) * time.Second

var basicAuthCache = cache.New(60*time.Second, 60*time.Minute)

var cacheGroup singleflight.Group

// BasicAuthKeyIsValid uses a username instead of
type BasicAuthKeyIsValid struct {
	BaseMiddleware

	bodyUserRegexp     *regexp.Regexp
	bodyPasswordRegexp *regexp.Regexp
}

func (k *BasicAuthKeyIsValid) Name() string {
	return "BasicAuthKeyIsValid"
}

// EnabledForSpec checks if UseBasicAuth is set in the API definition.
func (k *BasicAuthKeyIsValid) EnabledForSpec() bool {
	if !k.Spec.UseBasicAuth {
		return false
	}

	var err error

	if k.Spec.BasicAuth.ExtractFromBody {
		if k.Spec.BasicAuth.BodyUserRegexp == "" || k.Spec.BasicAuth.BodyPasswordRegexp == "" {
			k.Logger().Error("Basic Auth configured to extract credentials from body, but regexps are empty")
			return false
		}

		k.bodyUserRegexp, err = regexp.Compile(k.Spec.BasicAuth.BodyUserRegexp)
		if err != nil {
			k.Logger().WithError(err).Error("Invalid user body regexp")
			return false
		}

		k.bodyPasswordRegexp, err = regexp.Compile(k.Spec.BasicAuth.BodyPasswordRegexp)
		if err != nil {
			k.Logger().WithError(err).Error("Invalid user password regexp")
			return false
		}
	}

	return true
}

// requestForBasicAuth sends error code and message along with WWW-Authenticate header to client.
func (k *BasicAuthKeyIsValid) requestForBasicAuth(w http.ResponseWriter, msg string) (error, int) {
	authReply := "Basic realm=\"" + k.Spec.Name + "\""

	w.Header().Add(header.WWWAuthenticate, authReply)
	return errors.New(msg), http.StatusUnauthorized
}

// getAuthType overrides BaseMiddleware.getAuthType.
func (k *BasicAuthKeyIsValid) getAuthType() string {
	return apidef.BasicType
}

func (k *BasicAuthKeyIsValid) basicAuthHeaderCredentials(w http.ResponseWriter, r *http.Request) (username, password string, err error, code int) {
	token, _ := k.getAuthToken(k.getAuthType(), r)
	logger := k.Logger().WithField("key", k.Gw.obfuscateKey(token))
	if token == "" {
		// No header value, fail
		err, code = k.requestForBasicAuth(w, "Authorization field missing")
		return
	}

	bits := strings.Split(token, " ")
	if len(bits) != 2 {
		// Header malformed
		logger.Info("Attempted access with malformed header, header not in basic auth format.")

		err, code = errors.New("Attempted access with malformed header, header not in basic auth format"), http.StatusBadRequest
		return
	}

	// Decode the username:password string
	authvaluesStr, err := base64.StdEncoding.DecodeString(bits[1])
	if err != nil {
		logger.Info("Base64 Decoding failed of basic auth data: ", err)

		err, code = errors.New("Attempted access with malformed header, auth data not encoded correctly"), http.StatusBadRequest
		return
	}

	authValues := strings.Split(string(authvaluesStr), ":")
	if len(authValues) != 2 {
		// Header malformed
		logger.Info("Attempted access with malformed header, values not in basic auth format.")

		err, code = errors.New("Attempted access with malformed header, values not in basic auth format"), http.StatusBadRequest
		return
	}

	username, password = authValues[0], authValues[1]
	return
}

func (k *BasicAuthKeyIsValid) basicAuthBodyCredentials(w http.ResponseWriter, r *http.Request) (username, password string, err error, code int) {
	body, _ := ioutil.ReadAll(r.Body)
	r.Body = ioutil.NopCloser(bytes.NewReader(body))

	userMatch := k.bodyUserRegexp.FindAllSubmatch(body, 1)
	if len(userMatch) == 0 {
		err, code = errors.New("Body do not contain username"), http.StatusBadRequest
		return
	}

	if len(userMatch[0]) < 2 {
		err, code = errors.New("username should be inside regexp match group"), http.StatusBadRequest
		return
	}

	passMatch := k.bodyPasswordRegexp.FindAllSubmatch(body, 1)

	if len(passMatch) == 0 {
		err, code = errors.New("Body do not contain password"), http.StatusBadRequest
		return
	}

	if len(passMatch[0]) < 2 {
		err, code = errors.New("password should be inside regexp match group"), http.StatusBadRequest
		return
	}

	username, password = string(userMatch[0][1]), string(passMatch[0][1])

	return username, password, nil, 0
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (k *BasicAuthKeyIsValid) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if ctxGetRequestStatus(r) == StatusOkAndIgnore {
		return nil, http.StatusOK
	}

	username, password, err, code := k.basicAuthHeaderCredentials(w, r)
	token := r.Header.Get(header.Authorization)
	if err != nil {
		if k.Spec.BasicAuth.ExtractFromBody {
			w.Header().Del(header.WWWAuthenticate)
			username, password, err, code = k.basicAuthBodyCredentials(w, r)
		} else {
			k.Logger().Warn("Attempted access with malformed header, no auth header found.")
		}

		if err != nil {
			return err, code
		}
	}

	// Check if API key valid
	keyName := username
	logger := k.Logger().WithField("key", k.Gw.obfuscateKey(keyName))
	session, keyExists := k.CheckSessionAndIdentityForValidKey(keyName, r)
	keyName = session.KeyID

	if !keyExists {
		if k.Gw.GetConfig().HashKeyFunction == "" {
			logger.Warning("Attempted access with non-existent user.")
			return k.handleAuthFail(w, r, token)
		} else { // check for key with legacy format "org_id" + "user_name"
			logger.Info("Could not find user, falling back to legacy format key.")
			legacyKeyName := strings.TrimPrefix(username, k.Spec.OrgID)
			keyName, _ = storage.GenerateToken(k.Spec.OrgID, legacyKeyName, "")
			session, keyExists = k.CheckSessionAndIdentityForValidKey(keyName, r)
			keyName = session.KeyID
			if !keyExists {
				logger.Warning("Attempted access with non-existent user.")
				return k.handleAuthFail(w, r, token)
			}
		}
	}

	if err := k.checkPassword(&session, password, logger); err != nil {
		logger.WithError(err).Warn("Attempted access with existing user, failed password check.")
		return k.handleAuthFail(w, r, token)
	}

	// Set session state on context, we will need it later
	switch k.Spec.BaseIdentityProvidedBy {
	case apidef.BasicAuthUser, apidef.UnsetAuth:
		ctxSetSession(r, &session, false, k.Gw.GetConfig().HashKeys)
	}

	return nil, http.StatusOK
}

var errUnauthorized = errors.New("Unauthorized")

func (k *BasicAuthKeyIsValid) checkPassword(session *user.SessionState, plainPassword string, logger *logrus.Entry) error {
	switch session.BasicAuthData.Hash {
	case user.HashPlainText:
		if session.BasicAuthData.Password != plainPassword {
			return errUnauthorized
		}

	case user.HashSha256, user.HashMurmur32, user.HashMurmur64, user.HashMurmur128:
		// Verify we have a valid Hash value
		hashAlgo := string(session.BasicAuthData.Hash)

		// Checks the storage algo picked
		hashedPassword := storage.HashStr(plainPassword, hashAlgo)
		if session.BasicAuthData.Password != hashedPassword {
			return errUnauthorized
		}

	case user.HashBCrypt:
		fallthrough

	default:
		if err := k.compareHashAndPassword(session.BasicAuthData.Password, plainPassword, logger); err != nil {
			return err
		}
	}
	return nil
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

	hasher := murmur3.New64()
	hasher.Write(password)
	basicAuthCache.Set(string(hashedPassword), string(hasher.Sum(nil)), cacheDuration)

	return nil
}

func (k *BasicAuthKeyIsValid) compareHashAndPassword(hash string, password string, logEntry *logrus.Entry) error {
	passwordBytes := []byte(password)
	hashBytes := []byte(hash)

	if k.Spec.BasicAuth.DisableCaching {
		logEntry.Debug("cache disabled")
		return bcrypt.CompareHashAndPassword(hashBytes, passwordBytes)
	}

	cacheTTL := defaultBasicAuthTTL // set a default TTL, then override based on BasicAuth.CacheTTL
	if k.Spec.BasicAuth.CacheTTL > 0 {
		cacheTTL = time.Duration(k.Spec.BasicAuth.CacheTTL) * time.Second
	}

	cachedPass, inCache := basicAuthCache.Get(hash)
	if !inCache {
		logEntry.Debug("cache enabled: miss: bcrypt")
		_, err, _ := cacheGroup.Do(hash+"."+password, func() (interface{}, error) {
			return nil, k.doBcryptWithCache(cacheTTL, hashBytes, passwordBytes)
		})

		return err
	}

	hasher := murmur3.New64()
	hasher.Write(passwordBytes)

	if cachedPass.(string) != string(hasher.Sum(nil)) {
		logEntry.Warn("cache enabled: hit: failed auth: bcrypt")
		return bcrypt.CompareHashAndPassword(hashBytes, passwordBytes)
	}

	logEntry.Debug("cache enabled: hit: success")
	return nil
}

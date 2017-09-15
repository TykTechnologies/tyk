package main

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/Sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"

	"github.com/TykTechnologies/tyk/apidef"
)

// BasicAuthKeyIsValid uses a username instead of
type BasicAuthKeyIsValid struct {
	BaseMiddleware
}

func (k *BasicAuthKeyIsValid) Name() string {
	return "BasicAuthKeyIsValid"
}

// requestForBasicAuth sends error code and message along with WWW-Authenticate header to client.
func (k *BasicAuthKeyIsValid) requestForBasicAuth(w http.ResponseWriter, msg string) (error, int) {
	authReply := "Basic realm=\"" + k.Spec.Name + "\""

	w.Header().Add("WWW-Authenticate", authReply)
	return errors.New(msg), 401
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (k *BasicAuthKeyIsValid) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	token := r.Header.Get("Authorization")
	if token == "" {
		// No header value, fail
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": requestIP(r),
		}).Info("Attempted access with malformed header, no auth header found.")

		return k.requestForBasicAuth(w, "Authorization field missing")
	}

	bits := strings.Split(token, " ")
	if len(bits) != 2 {
		// Header malformed
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": requestIP(r),
		}).Info("Attempted access with malformed header, header not in basic auth format.")

		return errors.New("Attempted access with malformed header, header not in basic auth format"), 400
	}

	// Decode the username:password string
	authvaluesStr, err := base64.StdEncoding.DecodeString(bits[1])
	if err != nil {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": requestIP(r),
		}).Info("Base64 Decoding failed of basic auth data: ", err)

		return errors.New("Attempted access with malformed header, auth data not encoded correctly"), 400
	}

	authValues := strings.Split(string(authvaluesStr), ":")
	if len(authValues) != 2 {
		// Header malformed
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": requestIP(r),
		}).Info("Attempted access with malformed header, values not in basic auth format.")

		return errors.New("Attempted access with malformed header, values not in basic auth format"), 400
	}

	// Check if API key valid
	keyName := k.Spec.OrgID + authValues[0]
	session, keyExists := k.CheckSessionAndIdentityForValidKey(keyName)
	if !keyExists {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": requestIP(r),
			"key":    keyName,
		}).Info("Attempted access with non-existent user.")

		// Fire Authfailed Event
		AuthFailed(k, r, token)

		// Report in health check
		reportHealthValue(k.Spec, KeyFailure, "-1")

		return k.requestForBasicAuth(w, "User not authorised")
	}

	// Ensure that the username and password match up
	var passMatch bool
	switch session.BasicAuthData.Hash {
	case HashBCrypt:
		err := bcrypt.CompareHashAndPassword([]byte(session.BasicAuthData.Password), []byte(authValues[1]))
		if err == nil {
			passMatch = true
		}
	case HashPlainText:
		if session.BasicAuthData.Password == authValues[1] {
			passMatch = true
		}
	}

	if !passMatch {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": requestIP(r),
			"key":    keyName,
		}).Info("Attempted access with existing user but failed password check.")

		// Fire Authfailed Event
		AuthFailed(k, r, token)

		// Report in health check
		reportHealthValue(k.Spec, KeyFailure, "-1")

		return k.requestForBasicAuth(w, "User not authorised")
	}

	// Set session state on context, we will need it later
	switch k.Spec.BaseIdentityProvidedBy {
	case apidef.BasicAuthUser, apidef.UnsetAuth:
		ctxSetSession(r, &session)
		ctxSetAuthToken(r, keyName)
	}

	// Request is valid, carry on
	return nil, 200
}

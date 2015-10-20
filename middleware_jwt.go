package main

import "net/http"

import (
	"errors"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
	"io"
)

// KeyExists will check if the key being used to access the API is in the request data,
// and then if the key is in the storage engine
type JWTMiddleware struct {
	*TykMiddleware
}

func (k JWTMiddleware) New() {}

// GetConfig retrieves the configuration from the API config
func (k *JWTMiddleware) GetConfig() (interface{}, error) {
	return k.TykMiddleware.Spec.APIDefinition.Auth, nil
}

func (k *JWTMiddleware) copyResponse(dst io.Writer, src io.Reader) {
	io.Copy(dst, src)
}

func (k *JWTMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	thisConfig := k.TykMiddleware.Spec.APIDefinition.Auth
	var thisSessionState SessionState
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
			"origin": r.RemoteAddr,
		}).Info("Attempted access with malformed header, no JWT auth header found.")

		log.Debug("Looked in: ", thisConfig.AuthHeaderName)
		log.Debug("Raw data was: ", rawJWT)
		log.Debug("Headers are: ", r.Header)

		return errors.New("Authorization field missing"), 400
	}

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
		} else {
			log.Warning("No signing method found in API Definition, defaulting to HMAC")
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
		}

		tykId = token.Header["kid"].(string)
		var keyExists bool
		thisSessionState, keyExists = k.TykMiddleware.CheckSessionAndIdentityForValidKey(tykId)

		if !keyExists {
			return nil, errors.New("Token ivalid, key not found.")
		}

		return []byte(thisSessionState.JWTData.Secret), nil
	})

	if err == nil && token.Valid {
		// all good to go
		context.Set(r, SessionData, thisSessionState)
		context.Set(r, AuthHeaderValue, tykId)
		return nil, 200

	} else {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": r.RemoteAddr,
			"key":    token.Header["kid"],
		}).Info("Attempted JWT access with non-existent key.")

		if err != nil {
			log.Error("Token validtion errored: ", err)
		}

		// Fire Authfailed Event
		AuthFailed(k.TykMiddleware, r, tykId)

		// Report in health check
		ReportHealthCheckValue(k.Spec.Health, KeyFailure, "1")

		return errors.New("Key not authorised"), 403
	}
}

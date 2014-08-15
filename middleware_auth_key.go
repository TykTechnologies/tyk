package main

import "net/http"

import (
	"errors"
	"github.com/Sirupsen/logrus"
	"github.com/gorilla/context"
	"github.com/mitchellh/mapstructure"
)

// KeyExists will check if the key being used to access the API is in the request data,
// and then if the key is in the storage engine
type AuthKey struct {
	TykMiddleware
}

type AuthKeyConfiguration struct {
	Auth struct {
		AuthHeaderName string `mapstructure:"auth_header_name" bson:"auth_header_name" json:"auth_header_name"`
	} `mapstructure:"auth" bson:"auth" json:"auth"`
}

func (k AuthKey) New() {}

// GetConfig retrieves the configuration from the API config
func (k *AuthKey) GetConfig() (interface{}, error) {
	var thisModuleConfig AuthKeyConfiguration

	err := mapstructure.Decode(k.TykMiddleware.Spec.APIDefinition.RawData, &thisModuleConfig)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	return thisModuleConfig, nil
}

func (k *AuthKey) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	var thisConfig AuthKeyConfiguration
	thisConfig = configuration.(AuthKeyConfiguration)

	authHeaderValue := r.Header.Get(thisConfig.Auth.AuthHeaderName)
	if authHeaderValue == "" {
		// No header value, fail
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": r.RemoteAddr,
		}).Info("Attempted access with malformed header, no auth header found.")

		return errors.New("Authorization field missing"), 400
	}

	// Check if API key valid
	keyExists, thisSessionState := authManager.IsKeyAuthorised(authHeaderValue)
	if !keyExists {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": r.RemoteAddr,
			"key":    authHeaderValue,
		}).Info("Attempted access with non-existent key.")

		return errors.New("Key not authorised"), 403
	}

	// Set session state on context, we will need it later
	context.Set(r, SessionData, thisSessionState)
	context.Set(r, AuthHeaderValue, authHeaderValue)

	return nil, 200
}

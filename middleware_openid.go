package main

import "net/http"

import (
	"crypto/md5"
	"errors"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/TykTechnologies/openid2go/openid"
	"github.com/gorilla/context"
)

type OpenIDMW struct {
	*TykMiddleware
	providerConfiguration     *openid.Configuration
	provider_client_policymap map[string]map[string]string
}

func (k OpenIDMW) New() {
	k.provider_client_policymap = make(map[string]map[string]string)
	// Create an OpenID Configuration and store
	var configErr error
	k.providerConfiguration, configErr = openid.NewConfiguration(openid.ProvidersGetter(k.getProviders),
		openid.ErrorHandler(k.dummyErrorHandler))

	if configErr != nil {
		log.Error("OpenID configuration error: ", configErr)
	}
}

func (k *OpenIDMW) getProviders() ([]openid.Provider, error) {
	providers := []openid.Provider{}
	for _, provider := range k.TykMiddleware.Spec.OpenIDOptions.Providers {
		iss := provider.Issuer
		providerClientArray := make([]string, len(provider.ClientIDs))

		i := 0
		for clientID, policyID := range provider.ClientIDs {
			k.provider_client_policymap[iss][clientID] = policyID
			providerClientArray[i] = clientID
			i++
		}

		p, err := openid.NewProvider(iss, providerClientArray)

		if err != nil {
			log.WithFields(logrus.Fields{
				"provider": iss,
			}).Error("Failed to create provider: ", err)
		} else {
			providers = append(providers, p)
		}
	}

	return providers, nil
}

// We don't want any of the error handling, we use our own
func (k *OpenIDMW) dummyErrorHandler(e error, w http.ResponseWriter, r *http.Request) bool {
	return true
}

// GetConfig retrieves the configuration from the API config
func (k *OpenIDMW) GetConfig() (interface{}, error) {
	return nil, nil
}

func (k *OpenIDMW) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	// 1. Validate the JWT
	user, token, halt := openid.AuthenticateOIDWithUser(k.providerConfiguration, w, r)

	// 2. Generate the internal representation for the key
	if halt {
		// Fire Authfailed Event
		k.reportLoginFailure("[JWT]", r)
		return errors.New("Key not authorised"), 403
	}

	// 3. Create or set the session to match
	data := []byte(user.ID)
	tokenID := fmt.Sprintf("%x", md5.Sum(data))
	SessionID := k.TykMiddleware.Spec.OrgID + tokenID

	iss, found := token.Claims["iss"]
	clients, cfound := token.Claims["aud"]

	if !found && !cfound {
		log.Error("No issuer or audiences found!")
		k.reportLoginFailure(SessionID, r)
		return errors.New("Key not authorised"), 403
	}

	clientSet, foundIssuer := k.provider_client_policymap[iss.(string)]
	if !foundIssuer {
		log.Error("No issuer or audiences found!")
		k.reportLoginFailure(SessionID, r)
		return errors.New("Key not authorised"), 403
	}

	policyID := ""
	switch v := clients.(type) {
	case string:
		policyID = v
	case []interface{}:
		for _, audVal := range v {
			policy, foundPolicy := clientSet[audVal.(string)]
			if foundPolicy {
				policyID = policy
				break
			}
		}
	}

	if policyID == "" {
		log.Error("No matching policy found!")
		k.reportLoginFailure(SessionID, r)
		return errors.New("Key not authorised"), 403
	}

	thisSessionState, keyExists := k.TykMiddleware.CheckSessionAndIdentityForValidKey(SessionID)
	if !keyExists {
		// Create it
		log.Debug("Key does not exist, creating")
		thisSessionState = SessionState{}

		// We need a base policy as a template, either get it from the token itself OR a proxy client ID within Tyk
		newSessionState, err := generateSessionFromPolicy(policyID,
			k.TykMiddleware.Spec.APIDefinition.OrgID,
			true)

		if err != nil {
			k.reportLoginFailure(SessionID, r)
			log.Error("Could not find a valid policy to apply to this token!")
			return errors.New("Key not authorized: no matching policy"), 403
		}

		thisSessionState = newSessionState
		thisSessionState.MetaData = map[string]interface{}{"TykJWTSessionID": SessionID}

		// Update the session in the session manager in case it gets called again
		k.Spec.SessionManager.UpdateSession(SessionID, thisSessionState, k.Spec.APIDefinition.SessionLifetime)
		log.Debug("Policy applied to key")

	}

	// 4. Set session state on context, we will need it later
	context.Set(r, SessionData, thisSessionState)
	context.Set(r, AuthHeaderValue, SessionID)

	return nil, 200
}

func (k *OpenIDMW) reportLoginFailure(tykId string, r *http.Request) {
	// Fire Authfailed Event
	AuthFailed(k.TykMiddleware, r, tykId)

	// Report in health check
	ReportHealthCheckValue(k.Spec.Health, KeyFailure, "1")
}

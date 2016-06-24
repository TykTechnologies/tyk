package main

import "net/http"

import (
	"crypto/md5"
	b64 "encoding/base64"
	"errors"
	"fmt"

	"github.com/Sirupsen/logrus"
	"github.com/TykTechnologies/openid2go/openid"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
)

var OIDPREFIX string = "openid"

type OpenIDMW struct {
	*TykMiddleware
	providerConfiguration     *openid.Configuration
	provider_client_policymap map[string]map[string]string
}

func (k *OpenIDMW) New() {
	k.provider_client_policymap = make(map[string]map[string]string)
	// Create an OpenID Configuration and store
	var configErr error
	k.providerConfiguration, configErr = openid.NewConfiguration(openid.ProvidersGetter(k.getProviders),
		openid.ErrorHandler(k.dummyErrorHandler))

	if configErr != nil {
		log.WithFields(logrus.Fields{
			"prefix": OIDPREFIX,
		}).Error("OpenID configuration error: ", configErr)
	}
}

func (k *OpenIDMW) getProviders() ([]openid.Provider, error) {
	providers := []openid.Provider{}
	log.Debug("Setting up providers: ", k.TykMiddleware.Spec.OpenIDOptions.Providers)
	for _, provider := range k.TykMiddleware.Spec.OpenIDOptions.Providers {
		iss := provider.Issuer
		log.Debug("Setting up Issuer: ", iss)
		providerClientArray := make([]string, len(provider.ClientIDs))

		i := 0
		for clientID, policyID := range provider.ClientIDs {
			clID, _ := b64.StdEncoding.DecodeString(clientID)
			thisClientID := string(clID)
			if k.provider_client_policymap[iss] == nil {
				k.provider_client_policymap[iss] = map[string]string{thisClientID: policyID}
			} else {
				k.provider_client_policymap[iss][thisClientID] = policyID
			}

			log.Debug("--> Setting up client: ", thisClientID, " with policy: ", policyID)
			providerClientArray[i] = thisClientID
			i++
		}

		p, err := openid.NewProvider(iss, providerClientArray)

		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix":   OIDPREFIX,
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
	log.WithFields(logrus.Fields{
		"prefix": OIDPREFIX,
	}).Warning("JWT Invalid: ", e)
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
	claims := token.Claims.(jwt.MapClaims)
	iss, found := claims["iss"]
	clients, cfound := claims["aud"]

	if !found && !cfound {
		log.WithFields(logrus.Fields{
			"prefix": OIDPREFIX,
		}).Error("No issuer or audiences found!")
		k.reportLoginFailure("[NOT GENERATED]", r)
		return errors.New("Key not authorised"), 403
	}

	clientSet, foundIssuer := k.provider_client_policymap[iss.(string)]
	if !foundIssuer {
		log.WithFields(logrus.Fields{
			"prefix": OIDPREFIX,
		}).Error("No issuer or audiences found!")
		k.reportLoginFailure("[NOT GENERATED]", r)
		return errors.New("Key not authorised"), 403
	}

	policyID := ""
	thisClientID := ""
	switch v := clients.(type) {
	case string:
		policyID = clientSet[v]
		thisClientID = v
	case []interface{}:
		for _, audVal := range v {
			policy, foundPolicy := clientSet[audVal.(string)]
			if foundPolicy {
				thisClientID = audVal.(string)
				policyID = policy
				break
			}
		}
	}

	if policyID == "" {
		log.WithFields(logrus.Fields{
			"prefix": OIDPREFIX,
		}).Error("No matching policy found!")
		k.reportLoginFailure("[NOT GENERATED]", r)
		return errors.New("Key not authorised"), 403
	}

	data := []byte(user.ID)
	tokenID := fmt.Sprintf("%x", md5.Sum(data))
	SessionID := k.TykMiddleware.Spec.OrgID + tokenID
	if k.Spec.OpenIDOptions.SegregateByClient {
		// We are segregating by client, so use it as part of the internal token
		log.Debug("Client ID:", thisClientID)
		SessionID = k.TykMiddleware.Spec.OrgID + fmt.Sprintf("%x", md5.Sum([]byte(thisClientID))) + tokenID
	}

	log.Debug("Generated Session ID: ", SessionID)

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
			log.WithFields(logrus.Fields{
				"prefix": OIDPREFIX,
			}).Error("Could not find a valid policy to apply to this token!")
			return errors.New("Key not authorized: no matching policy"), 403
		}

		thisSessionState = newSessionState
		thisSessionState.MetaData = map[string]interface{}{"TykJWTSessionID": SessionID, "ClientID": thisClientID}
		thisSessionState.Alias = thisClientID + ":" + user.ID

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
	log.WithFields(logrus.Fields{
		"prefix": OIDPREFIX,
		"key":    tykId,
	}).Warning("Attempted access with invalid key.")

	// Fire Authfailed Event
	AuthFailed(k.TykMiddleware, r, tykId)

	// Report in health check
	ReportHealthCheckValue(k.Spec.Health, KeyFailure, "1")
}

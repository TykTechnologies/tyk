package main

import (
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/Sirupsen/logrus"
	"github.com/dgrijalva/jwt-go"

	"github.com/TykTechnologies/openid2go/openid"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"
)

const OIDPREFIX = "openid"

type OpenIDMW struct {
	BaseMiddleware
	providerConfiguration     *openid.Configuration
	provider_client_policymap map[string]map[string]string
	lock                      sync.RWMutex
	providerConfigs           map[string]apidef.OIDProviderConfig
}

func (k *OpenIDMW) Name() string {
	return "OpenIDMW"
}

func (k *OpenIDMW) EnabledForSpec() bool {
	return k.Spec.UseOpenID
}

func (k *OpenIDMW) Init() {
	k.provider_client_policymap = make(map[string]map[string]string)
	// Create an OpenID Configuration and store
	var err error
	k.providerConfiguration, err = openid.NewConfiguration(openid.ProvidersGetter(k.getProviders),
		openid.ErrorHandler(k.dummyErrorHandler))

	if err != nil {
		k.Logger().WithError(err).Error("OpenID configuration error")
	}

	// prepare map issuer->config to lookup configs when processing requests
	k.providerConfigs = make(map[string]apidef.OIDProviderConfig)
	for _, providerConf := range k.Spec.OpenIDOptions.Providers {
		k.providerConfigs[providerConf.Issuer] = providerConf
	}
}

func (k *OpenIDMW) getProviders() ([]openid.Provider, error) {
	providers := []openid.Provider{}
	k.Logger().Debug("Setting up providers: ", k.Spec.OpenIDOptions.Providers)
	for _, provider := range k.Spec.OpenIDOptions.Providers {
		iss := provider.Issuer
		k.Logger().Debug("Setting up Issuer: ", iss)
		providerClientArray := make([]string, len(provider.ClientIDs))

		i := 0
		for clientID, policyID := range provider.ClientIDs {
			clID, _ := base64.StdEncoding.DecodeString(clientID)
			clientID := string(clID)

			k.lock.Lock()
			if k.provider_client_policymap[iss] == nil {
				k.provider_client_policymap[iss] = map[string]string{clientID: policyID}
			} else {
				k.provider_client_policymap[iss][clientID] = policyID
			}
			k.lock.Unlock()

			k.Logger().Debug("--> Setting up client: ", clientID, " with policy: ", policyID)
			providerClientArray[i] = clientID
			i++
		}

		p, err := openid.NewProvider(iss, providerClientArray)

		if err != nil {
			k.Logger().WithError(err).WithFields(logrus.Fields{
				"provider": iss,
			}).Error("Failed to create provider")
		} else {
			providers = append(providers, p)
		}
	}

	return providers, nil
}

// We don't want any of the error handling, we use our own
func (k *OpenIDMW) dummyErrorHandler(e error, w http.ResponseWriter, r *http.Request) bool {
	k.Logger().WithError(e).Warning("JWT Invalid")
	return true
}

func (k *OpenIDMW) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	logger := k.Logger()
	// 1. Validate the JWT
	ouser, token, halt := openid.AuthenticateOIDWithUser(k.providerConfiguration, w, r)

	// 2. Generate the internal representation for the key
	if halt {
		// Fire Authfailed Event
		k.reportLoginFailure("[JWT]", r)
		return errors.New("Key not authorised"), http.StatusUnauthorized
	}

	// 3. Create or set the session to match
	iss, found := token.Claims.(jwt.MapClaims)["iss"]
	clients, cfound := token.Claims.(jwt.MapClaims)["aud"]

	if !found && !cfound {
		logger.Error("No issuer or audiences found!")
		k.reportLoginFailure("[NOT GENERATED]", r)
		return errors.New("Key not authorised"), http.StatusUnauthorized
	}

	providerConf, ok := k.providerConfigs[iss.(string)]
	if !ok {
		logger.Error("No issuer or audiences found!")
		k.reportLoginFailure("[NOT GENERATED]", r)
		return errors.New("Key not authorised"), http.StatusUnauthorized
	}

	// decide if we use policy ID from provider client settings or list of policies from scope-policy mapping
	useScope := providerConf.ScopeFieldName != "" && providerConf.ScopeToPolicyMapping != nil

	k.lock.RLock()
	clientSet, foundIssuer := k.provider_client_policymap[iss.(string)]
	k.lock.RUnlock()
	if !foundIssuer {
		logger.Error("No issuer or audiences found!")
		k.reportLoginFailure("[NOT GENERATED]", r)
		return errors.New("Key not authorised"), http.StatusUnauthorized
	}

	policyID := ""
	clientID := ""
	switch v := clients.(type) {
	case string:
		k.lock.RLock()
		policyID = clientSet[v]
		k.lock.RUnlock()
		clientID = v
	case []interface{}:
		for _, audVal := range v {
			k.lock.RLock()
			policy, foundPolicy := clientSet[audVal.(string)]
			k.lock.RUnlock()
			if foundPolicy {
				clientID = audVal.(string)
				policyID = policy
				break
			}
		}
	}

	if !useScope && policyID == "" {
		logger.Error("No matching policy found!")
		k.reportLoginFailure("[NOT GENERATED]", r)
		return errors.New("Key not authorised"), http.StatusUnauthorized
	}

	data := []byte(ouser.ID)
	keyID := fmt.Sprintf("%x", md5.Sum(data))
	sessionID := generateToken(k.Spec.OrgID, keyID)

	if k.Spec.OpenIDOptions.SegregateByClient {
		// We are segregating by client, so use it as part of the internal token
		logger.Debug("Client ID:", clientID)
		sessionID = generateToken(k.Spec.OrgID, fmt.Sprintf("%x", md5.Sum([]byte(clientID)))+keyID)
	}

	logger.Debug("Generated Session ID: ", sessionID)

	var policiesToApply []string
	if !useScope {
		policiesToApply = append(policiesToApply, policyID)
	} else {
		if scope := getScopeFromClaim(token.Claims.(jwt.MapClaims), providerConf.ScopeFieldName); scope != nil {
			// add all policies matched from scope-policy mapping
			policiesToApply = mapScopeToPolicies(providerConf.ScopeToPolicyMapping, scope)
		}
	}

	session, exists := k.CheckSessionAndIdentityForValidKey(sessionID, r)
	if !exists {
		// Create it
		logger.Debug("Key does not exist, creating")
		session = user.SessionState{}

		if !useScope {
			// We need a base policy as a template, either get it from the token itself OR a proxy client ID within Tyk
			newSession, err := generateSessionFromPolicy(policyID,
				k.Spec.OrgID,
				true)

			if err != nil {
				k.reportLoginFailure(sessionID, r)
				logger.Error("Could not find a valid policy to apply to this token!")
				return errors.New("Key not authorized: no matching policy"), http.StatusForbidden
			}

			session = newSession
		}

		session.OrgID = k.Spec.OrgID
		session.MetaData = map[string]interface{}{"TykJWTSessionID": sessionID, "ClientID": clientID}
		session.Alias = clientID + ":" + ouser.ID

		// Update the session in the session manager in case it gets called again
		logger.Debug("Policy applied to key")
	}
	// apply new policy to session if any and update session
	session.SetPolicies(policiesToApply...)
	if err := k.ApplyPolicies(sessionID, &session); err != nil {
		k.Logger().WithError(err).Error("Could not apply new policy from OIDC client to session")
		return errors.New("Key not authorized: could not apply new policy"), http.StatusForbidden
	}

	// 4. Set session state on context, we will need it later
	switch k.Spec.BaseIdentityProvidedBy {
	case apidef.OIDCUser, apidef.UnsetAuth:
		ctxSetSession(r, &session, sessionID, true)
	}
	ctxSetJWTContextVars(k.Spec, r, token)

	return nil, http.StatusOK
}

func (k *OpenIDMW) reportLoginFailure(tykId string, r *http.Request) {
	k.Logger().WithFields(logrus.Fields{
		"key": obfuscateKey(tykId),
	}).Warning("Attempted access with invalid key.")

	// Fire Authfailed Event
	AuthFailed(k, r, tykId)

	// Report in health check
	reportHealthValue(k.Spec, KeyFailure, "1")
}

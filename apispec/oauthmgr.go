package apispec

import (
	"github.com/lonelycode/osin"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"github.com/TykTechnologies/tyk/auth"
	"github.com/TykTechnologies/tyk/config"
	"encoding/json"
	"github.com/TykTechnologies/tyk/session"
)

// OAuthManager handles and wraps osin OAuth2 functions to handle authorise and access requests
type OAuthManager struct {
	API        *APISpec
	OsinServer *TykOsinServer
	Conf       *config.Config
}

// HandleAuthorisation creates the authorisation data for the request
func (o *OAuthManager) HandleAuthorisation(r *http.Request, complete bool, sessionState string) *osin.Response {
	resp := o.OsinServer.NewResponse()

	if ar := o.OsinServer.HandleAuthorizeRequest(resp, r); ar != nil {
		// Since this is called by the Reource provider (proxied API), we assume it has been approved
		ar.Authorized = true

		if complete {
			ar.UserData = sessionState
			o.OsinServer.FinishAuthorizeRequest(resp, r, ar)
		}
	}
	if resp.IsError && resp.InternalError != nil {
		log.Error(resp.InternalError)
	}

	return resp
}

// HandleAccess wraps an access request with osin's primitives
func (o *OAuthManager) HandleAccess(r *http.Request) *osin.Response {
	resp := o.OsinServer.NewResponse()
	var username string
	if ar := o.OsinServer.HandleAccessRequest(resp, r); ar != nil {

		var sess *session.SessionState
		if ar.Type == osin.PASSWORD {
			username = r.Form.Get("username")
			password := r.Form.Get("password")
			keyName := o.API.OrgID + username
			if o.Conf.HashKeys {
				// HASHING? FIX THE KEY
				keyName = auth.DoHash(keyName)
			}
			searchKey := "apikey-" + keyName
			log.Debug("Getting: ", searchKey)

			var err error
			sess, err = o.OsinServer.Storage.GetUser(searchKey)
			if err != nil {
				log.Warning("Attempted access with non-existent user (OAuth password flow).")
			} else {
				var passMatch bool
				if sess.BasicAuthData.Hash == session.HashBCrypt {
					err := bcrypt.CompareHashAndPassword([]byte(sess.BasicAuthData.Password), []byte(password))
					if err == nil {
						passMatch = true
					}
				}

				if sess.BasicAuthData.Hash == session.HashPlainText &&
					sess.BasicAuthData.Password == password {
					passMatch = true
				}

				if passMatch {
					log.Info("Here we are")
					ar.Authorized = true
					// not ideal, but we need to copy the sess state across
					pw := sess.BasicAuthData.Password
					hs := sess.BasicAuthData.Hash

					sess.BasicAuthData.Password = ""
					sess.BasicAuthData.Hash = ""
					asString, _ := json.Marshal(sess)
					ar.UserData = string(asString)

					sess.BasicAuthData.Password = pw
					sess.BasicAuthData.Hash = hs

					//log.Warning("Old Keys: ", sess.OauthKeys)
				}
			}
		} else {
			// Using a manual flow
			ar.Authorized = true
		}

		// Does the user have an old OAuth token for this client?
		if sess != nil && sess.OauthKeys != nil {
			log.Debug("There's keys here bill...")
			oldToken, foundKey := sess.OauthKeys[ar.Client.GetId()]
			if foundKey {
				log.Info("Found old token, revoking: ", oldToken)

				o.API.SessionManager.RemoveSession(oldToken)
			}
		}

		log.Debug("[OAuth] Finishing access request ")
		o.OsinServer.FinishAccessRequest(resp, r, ar)

		new_token, foundNewToken := resp.Output["access_token"]
		if username != "" && foundNewToken {
			log.Debug("Updating token data in key")
			if sess.OauthKeys == nil {
				sess.OauthKeys = make(map[string]string)
			}
			sess.OauthKeys[ar.Client.GetId()] = new_token.(string)
			log.Debug("New token: ", new_token.(string))
			log.Debug("Keys: ", sess.OauthKeys)

			keyName := o.API.OrgID + username

			log.Debug("Updating user:", keyName)
			err := o.API.SessionManager.UpdateSession(keyName, sess, auth.GetLifetime(o.API.APIDefinition, sess, o.Conf))
			if err != nil {
				log.Error(err)
			}
		}

	}
	if resp.IsError && resp.InternalError != nil {
		log.Error("ERROR: ", resp.InternalError)
	}

	return resp
}

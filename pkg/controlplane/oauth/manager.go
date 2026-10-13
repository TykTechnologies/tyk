package oauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/lonelycode/osin"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"

	"github.com/TykTechnologies/tyk/pkg/controlplane/keys"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

// KeyDataDeveloperEmail is the client metadata field promoted to the
// session alias on password-grant tokens.
const KeyDataDeveloperEmail = "tyk_developer_email"

// TokenIssuer is what the Manager needs from the key service beyond
// SessionFactory.
type TokenIssuer interface {
	SessionFactory
	GenerateToken(orgID, keyID string) string
	LifetimeFor(sess *user.SessionState, api *keys.APIInfo) int64
}

// Manager wraps osin to issue authorization codes and access tokens for
// one API. It is the gateway's OAuthManager with the runtime replaced by
// injected dependencies.
type Manager struct {
	API      keys.APIInfo
	Server   *Server
	Sessions keys.SessionStore
	Keys     TokenIssuer
	Cfg      func() Config
	Log      *logrus.Logger
}

func (o *Manager) log() *logrus.Logger {
	if o.Log == nil {
		return logrus.StandardLogger()
	}
	return o.Log
}

// Storage returns the server's extended storage.
func (o *Manager) Storage() ExtendedOsinStorageInterface {
	return o.Server.Storage
}

// HandleAuthorisation creates the authorisation data for the request. With
// complete, the request is finished with the session JSON as user data,
// which issues a code (response_type=code) or a token (response_type=token).
func (o *Manager) HandleAuthorisation(r *http.Request, complete bool, session string) *osin.Response {
	resp := o.Server.NewResponse()

	if ar := o.Server.HandleAuthorizeRequest(resp, r); ar != nil {
		// Since this is called by the Resource provider (proxied API), we assume it has been approved
		ar.Authorized = true

		if complete {
			ar.UserData = session
			o.Server.FinishAuthorizeRequest(resp, r, ar)
		}
	}
	if resp.IsError && resp.InternalError != nil {
		o.log().Error(resp.InternalError)
	}

	return resp
}

// JSONToFormValues if r has header Content-Type set to application/json this
// will decode request body as json to map[string]string and adds the key/value
// pairs in r.Form.
func JSONToFormValues(r *http.Request) error {
	if r.Header.Get("Content-Type") == "application/json" {
		var o map[string]string
		err := json.NewDecoder(r.Body).Decode(&o)
		if err != nil {
			return err
		}
		if len(o) > 0 {
			if r.Form == nil {
				r.Form = make(url.Values)
			}
			for k, v := range o {
				r.Form.Set(k, v)
			}
		}
	}
	return nil
}

// HandleAccess wraps an access request (grant types client_credentials,
// authorization_code, refresh_token, password) with osin's primitives.
func (o *Manager) HandleAccess(r *http.Request) *osin.Response {
	log := o.log()
	cfg := o.Cfg()
	resp := o.Server.NewResponse()
	// we are intentionally ignoring errors, because this is called again by
	// osin. We are only doing this to ensure r.Form is properly initialized in case
	// r.ParseForm was success
	r.ParseForm()
	if err := JSONToFormValues(r); err != nil {
		log.Errorf("trying to set url values decoded from json body :%v", err)
	}
	var username string

	if ar := o.Server.HandleAccessRequest(resp, r); ar != nil {

		var session *user.SessionState
		if ar.Type == osin.PASSWORD {
			username = r.Form.Get("username")
			password := r.Form.Get("password")
			searchKey := "apikey-" + storage.HashKey(o.API.OrgID+username, cfg.HashKeys)
			log.Debug("Getting: ", searchKey)

			var err error
			session, err = o.Server.Storage.GetUser(searchKey)
			if err != nil {
				log.Warning("Attempted access with non-existent user (OAuth password flow).")
			} else {
				var passMatch bool
				if session.BasicAuthData.Hash == user.HashBCrypt {
					err := bcrypt.CompareHashAndPassword([]byte(session.BasicAuthData.Password), []byte(password))
					if err == nil {
						passMatch = true
					}
				}

				if session.BasicAuthData.Hash == user.HashPlainText &&
					session.BasicAuthData.Password == password {
					passMatch = true
				}

				if passMatch {
					ar.Authorized = true
					// not ideal, but we need to copy the session state across
					pw := session.BasicAuthData.Password
					hs := session.BasicAuthData.Hash

					session.BasicAuthData.Password = ""
					session.BasicAuthData.Hash = ""
					asString, _ := json.Marshal(session)
					ar.UserData = string(asString)

					session.BasicAuthData.Password = pw
					session.BasicAuthData.Hash = hs
				}
			}
		} else {
			// Using a manual flow
			ar.Authorized = true
		}

		// Does the user have an old OAuth token for this client?
		if session != nil && session.OauthKeys != nil {
			log.Debug("There's keys here bill...")
			oldToken, foundKey := session.OauthKeys[ar.Client.GetId()]
			if foundKey {
				log.Info("Found old token, revoking: ", oldToken)
				o.Sessions.RemoveSession(o.API.OrgID, oldToken, false)
			}
		}

		log.Debug("[OAuth] Finishing access request ")
		o.Server.FinishAccessRequest(resp, r, ar)
		newToken, foundNewToken := resp.Output["access_token"]
		if username != "" && foundNewToken {
			log.Debug("Updating token data in key")
			if session.OauthKeys == nil {
				session.OauthKeys = make(map[string]string)
			}
			session.OauthKeys[ar.Client.GetId()] = newToken.(string)
			log.Debug("New token: ", newToken.(string))
			log.Debug("Keys: ", session.OauthKeys)

			// add oauth-client user_fields to session's meta
			if userData := ar.Client.GetUserData(); userData != nil {
				metadata, ok := userData.(map[string]interface{})
				if !ok {
					log.WithField("oauthClientID", ar.Client.GetId()).
						Error("Could not set session meta_data from oauth-client fields, type mismatch")
				} else {
					session.MetaData = metadata
					// set session alias to developer email as we do it for regular API keys created for developer
					if devEmail, found := session.MetaData[KeyDataDeveloperEmail].(string); found {
						session.Alias = devEmail
						// we don't need it in meta-data as we set it to alias
						delete(session.MetaData, KeyDataDeveloperEmail)
					}
				}
			}

			keyName := o.Keys.GenerateToken(o.API.OrgID, username)

			log.Debug("Updating user:", keyName)
			api := o.API
			err := o.Sessions.UpdateSession(keyName, session, o.Keys.LifetimeFor(session, &api), false)
			if err != nil {
				log.Error(err)
			}
		}
	}
	if resp.IsError {
		clientID := r.Form.Get("client_id")
		log.WithFields(logrus.Fields{
			"org_id":         o.API.OrgID,
			"client_id":      clientID,
			"response error": resp.StatusText,
			"response code":  resp.ErrorStatusCode,
		}).Error("[OAuth] OAuth response marked as error")
	}

	return resp
}

// RenderResponse encodes an osin response the way the gateway does: the
// output map as JSON (HTML unescaped), with redirect_to injected when the
// response carries a redirect, and an empty state removed.
func RenderResponse(osinResponse *osin.Response) []byte {
	if osinResponse.Output["state"] == "" {
		delete(osinResponse.Output, "state")
	}

	redirect, err := osinResponse.GetRedirectUrl()
	if err == nil {
		// Hack to inject redirect into response
		osinResponse.Output["redirect_to"] = redirect
	}

	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(&osinResponse.Output); err != nil {
		return nil
	}
	return buffer.Bytes()
}

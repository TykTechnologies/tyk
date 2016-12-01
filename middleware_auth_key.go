package main

import "net/http"

import (
	"bytes"
	"errors"
	"github.com/TykTechnologies/logrus"
	"github.com/TykTechnologies/tykcommon"
	"github.com/gorilla/context"
	"io"
	"io/ioutil"
)

// KeyExists will check if the key being used to access the API is in the request data,
// and then if the key is in the storage engine
type AuthKey struct {
	*TykMiddleware
}

func (k AuthKey) New() {}

// GetConfig retrieves the configuration from the API config
func (k *AuthKey) GetConfig() (interface{}, error) {
	return k.TykMiddleware.Spec.APIDefinition.Auth, nil
}

func (a *AuthKey) IsEnabledForSpec() bool {
	return true
}

func (k *AuthKey) copyResponse(dst io.Writer, src io.Reader) {
	io.Copy(dst, src)
}

func CopyRequest(r *http.Request) *http.Request {
	tempRes := new(http.Request)
	*tempRes = *r

	defer r.Body.Close()

	// Buffer body data - don't like thi but we would otherwise drain the request body
	var bodyBuffer bytes.Buffer
	bodyBuffer2 := new(bytes.Buffer)

	io.Copy(&bodyBuffer, r.Body)
	*bodyBuffer2 = bodyBuffer

	// Create new ReadClosers so we can split output
	r.Body = ioutil.NopCloser(&bodyBuffer)
	tempRes.Body = ioutil.NopCloser(bodyBuffer2)

	return tempRes
}

func (k *AuthKey) setContextVars(r *http.Request, token string) {
	// Flatten claims and add to context
	if k.Spec.EnableContextVars {
		cnt, contextFound := context.GetOk(r, ContextData)
		var contextDataObject map[string]interface{}
		if contextFound {
			// Key data
			contextDataObject = cnt.(map[string]interface{})
			contextDataObject["token"] = token
			context.Set(r, ContextData, contextDataObject)
		}

	}
}

func (k *AuthKey) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	var tempRes *http.Request

	thisConfig := k.TykMiddleware.Spec.APIDefinition.Auth

	key := r.Header.Get(thisConfig.AuthHeaderName)

	paramName := thisConfig.ParamName
	if thisConfig.UseParam || paramName != "" {
		if paramName == "" {
			paramName = thisConfig.AuthHeaderName
		}

		tempRes = CopyRequest(r)
		paramValue := tempRes.FormValue(paramName)

		// Only use the paramValue if it has an actual value
		if paramValue != "" {
			key = paramValue
		}
	}

	cookieName := thisConfig.CookieName
	if thisConfig.UseCookie || cookieName != "" {
		if cookieName == "" {
			cookieName = thisConfig.AuthHeaderName
		}
		if tempRes == nil {
			tempRes = CopyRequest(r)
		}

		authCookie, notFoundErr := tempRes.Cookie(cookieName)
		cookieValue := ""
		if notFoundErr == nil {
			cookieValue = authCookie.Value
		}

		if cookieValue != "" {
			key = cookieValue
		}
	}

	if key == "" {
		// No header value, fail
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": GetIPFromRequest(r),
		}).Info("Attempted access with malformed header, no auth header found.")

		return errors.New("Authorization field missing"), 401
	}

	// Ignore Bearer prefix on token if it exists
	key = stripBearer(key)

	// Check if API key valid
	thisSessionState, keyExists := k.TykMiddleware.CheckSessionAndIdentityForValidKey(key)
	if !keyExists {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": GetIPFromRequest(r),
			"key":    key,
		}).Info("Attempted access with non-existent key.")

		// Fire Authfailed Event
		AuthFailed(k.TykMiddleware, r, key)

		// Report in health check
		ReportHealthCheckValue(k.Spec.Health, KeyFailure, "1")

		return errors.New("Key not authorised"), 403
	}

	// Set session state on context, we will need it later
	if (k.TykMiddleware.Spec.BaseIdentityProvidedBy == tykcommon.AuthToken) || (k.TykMiddleware.Spec.BaseIdentityProvidedBy == tykcommon.UnsetAuth) {
		context.Set(r, SessionData, thisSessionState)
		context.Set(r, AuthHeaderValue, key)
		k.setContextVars(r, key)
	}

	return nil, 200
}

func AuthFailed(m *TykMiddleware, r *http.Request, authHeaderValue string) {
	go m.FireEvent(EVENT_AuthFailure,
		EVENT_AuthFailureMeta{
			EventMetaDefault: EventMetaDefault{Message: "Auth Failure", OriginatingRequest: EncodeRequestToEvent(r)},
			Path:             r.URL.Path,
			Origin:           GetIPFromRequest(r),
			Key:              authHeaderValue,
		})
}

package main

import (
	"net/http"
	"net/url"

	"github.com/TykTechnologies/logrus"
)

type MWStripAuthData struct {
	*TykMiddleware
}

type MWStripAuthDataConfig struct{}

// New lets you do any initialisations for the object can be done here
func (m *MWStripAuthData) New() {}

func (mw *MWStripAuthData) GetName() string {
	return "MWStripAuthData"
}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (m *MWStripAuthData) GetConfig() (interface{}, error) {
	var thisModuleConfig MiddlewareContextVarsConfig
	return thisModuleConfig, nil
}

func (a *MWStripAuthData) IsEnabledForSpec() bool {
	if a.Spec.StripAuthData {
		return true
	}
	return false
}

func (m *MWStripAuthData) StripAuth(r *http.Request, spec *APISpec) {
	if spec.APIDefinition.Auth.UseParam {
		// Remove the query string value
		copy, err := url.Parse(r.URL.String())
		if err != nil {
			log.WithFields(logrus.Fields{
				"path":   r.URL.Path,
				"origin": GetIPFromRequest(r),
				"key":    "",
			}).Error("Failed to copy URL to strip auth: ", err)
			return
		}

		q := copy.Query()
		n := spec.APIDefinition.Auth.ParamName
		if n == "" {
			n = spec.APIDefinition.Auth.AuthHeaderName
		}
		q.Del(n)
		copy.RawQuery = q.Encode()
		r.URL, err = r.URL.Parse(copy.String())
		if err != nil {
			log.WithFields(logrus.Fields{
				"path":   r.URL.Path,
				"origin": GetIPFromRequest(r),
				"key":    "",
			}).Error("Failed to set new URL: ", err)
			return
		}
	}

	n := spec.APIDefinition.Auth.AuthHeaderName
	if n == "" {
		n = "Authorization"
	}

	key := r.Header.Get(n)
	if key != "" {
		r.Header.Del(n)
	}
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (m *MWStripAuthData) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {

	if !m.Spec.StripAuthData {
		return nil, 200
	}

	m.StripAuth(r, m.Spec)

	return nil, 200
}

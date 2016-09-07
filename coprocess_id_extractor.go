// +build coprocess

package main

import (
	"github.com/Sirupsen/logrus"
	"github.com/gorilla/context"
	"github.com/mitchellh/mapstructure"
	"github.com/TykTechnologies/tykcommon"

	"crypto/md5"
	"net/http"
	"errors"
	"fmt"
)

// IdExtractorMiddleware is the basic CP middleware struct.
type IdExtractorMiddleware struct {
	*TykMiddleware
}

type IdExtractor interface {
	Extract(interface{}) string
}

type ValueExtractor struct {
	Config *tykcommon.MiddlewareIdExtractor
}

func(e *ValueExtractor) Extract(input interface{}) string {
	headerValue := input.(string)
	return headerValue
}

/*
"extract_from": "header",
"extract_with": "value",
"extractor_config": {
	"header_name": "Authorization"
}
*/

func CreateIdExtractorMiddleware(tykMwSuper *TykMiddleware) func(http.Handler) http.Handler {
	dMiddleware := &IdExtractorMiddleware{
		TykMiddleware: tykMwSuper,
	}

	return CreateMiddleware(dMiddleware, tykMwSuper)
}

// CoProcessMiddlewareConfig holds the middleware configuration.
type IdExtractorMiddlewareConfig struct {
	ConfigData map[string]string `mapstructure:"config_data" bson:"config_data" json:"config_data"`
}

// New lets you do any initialisations for the object can be done here
func (m *IdExtractorMiddleware) New() {}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (m *IdExtractorMiddleware) GetConfig() (interface{}, error) {
	var thisModuleConfig IdExtractorMiddlewareConfig

	err := mapstructure.Decode(m.TykMiddleware.Spec.APIDefinition.RawData, &thisModuleConfig)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "jsvm",
		}).Error(err)
		return nil, err
	}

	return thisModuleConfig, nil
}

func (m *IdExtractorMiddleware) IsEnabledForSpec() bool {
	var used bool
	if len(m.TykMiddleware.Spec.CustomMiddleware.IdExtractor.ExtractorConfig) > 0 {
		used = true
	}
	return used
}

func (m *IdExtractorMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	log.Println("*** IdExtractorMiddleware")
	log.Println("*** configuration", configuration)
	log.Println("*** spec (IdExtractorMiddleware)", m.TykMiddleware.Spec.CustomMiddleware.IdExtractor.ExtractorConfig)

	log.Println("*** extractwith", m.TykMiddleware.Spec.CustomMiddleware.IdExtractor.ExtractWith)

	var thisExtractor IdExtractor
	var extractorOutput, tokenID, SessionID string

	// Initialize a extractor based on the API spec.
	switch m.TykMiddleware.Spec.CustomMiddleware.IdExtractor.ExtractWith {
	case tykcommon.ValueExtractor:
		log.Println("Is a ValueExtractor.")
		thisExtractor = &ValueExtractor{
			Config: &m.TykMiddleware.Spec.CustomMiddleware.IdExtractor,
		}
	}

	// Check the extractor source, take the value and perform the extraction.
	switch m.TykMiddleware.Spec.CustomMiddleware.IdExtractor.ExtractFrom {
	case tykcommon.HeaderSource:
		var headerName, headerValue string

		// TODO: check if header_name is set
		headerName = m.TykMiddleware.Spec.CustomMiddleware.IdExtractor.ExtractorConfig["header_name"].(string)
		headerValue = r.Header.Get(headerName)

		if headerValue == "" {
			log.WithFields(logrus.Fields{
				"path":   r.URL.Path,
				"origin": GetIPFromRequest(r),
			}).Info("Attempted access with malformed header, no auth header found.")

			log.Debug("Looked in: ", headerName)
			log.Debug("Raw data was: ", headerValue)
			log.Debug("Headers are: ", r.Header)

			// m.reportLoginFailure(tykId, r)
			return errors.New("Authorization field missing"), 400
		}

		log.Println("Uses a HeaderSource.")
		// TODO: check if header_name setting exists!
		rawHeader := r.Header.Get(headerName)
		log.Println("rawHeader is", rawHeader)
		extractorOutput = thisExtractor.Extract(rawHeader)
	}

	// Prepare a session ID.

	data := []byte(extractorOutput)
	tokenID = fmt.Sprintf("%x", md5.Sum(data))
	SessionID = m.TykMiddleware.Spec.OrgID + tokenID

	fmt.Println("tokenID is", tokenID)
	fmt.Println("SessionID is", SessionID)

	thisSessionState, keyExists := m.TykMiddleware.CheckSessionAndIdentityForValidKey(SessionID)

	log.Println("thisSessionState is", thisSessionState)
	log.Println("keyExists is", keyExists)

	if keyExists {
		// Set context flag and ignore the CP auth!
		context.Set(r, SessionData, thisSessionState)
		context.Set(r, AuthHeaderValue, tokenID)

		context.Set(r, SkipCoProcessAuth, true)
	} else {
		// Follow the chain, the CP auth will be called.
	}

	return nil, 200
}

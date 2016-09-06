// +build coprocess

package main

import(
  "github.com/Sirupsen/logrus"
  // "github.com/gorilla/context"
  "github.com/mitchellh/mapstructure"
  // "github.com/TykTechnologies/tykcommon"

  "net/http"
)

// IdExtractorMiddleware is the basic CP middleware struct.
type IdExtractorMiddleware struct {
	*TykMiddleware
}

func CreateIdExtractorMiddleware(tykMwSuper *TykMiddleware) func(http.Handler) http.Handler {
	dMiddleware := &IdExtractorMiddleware{
		TykMiddleware:    tykMwSuper,
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
  if(len(m.TykMiddleware.Spec.CustomMiddleware.IdExtractor.ExtractorConfig) > 0 ) {
      used = true
  }
	return used
}

func (m *IdExtractorMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
  log.Println("*** IdExtractorMiddleware")
  return nil, 200
}

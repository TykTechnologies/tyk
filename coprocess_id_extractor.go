// +build coprocess

package main

import (
	"github.com/Sirupsen/logrus"
	"github.com/TykTechnologies/tykcommon"
	"github.com/gorilla/context"
	"github.com/mitchellh/mapstructure"
	// "gopkg.in/xmlpath.v2"
	"regexp"

	"crypto/md5"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type IdExtractor interface {
	ExtractAndCheck(*http.Request) (string, ReturnOverrides)
	PostProcess(*http.Request, SessionState, string)
	GenerateSessionID(string, *TykMiddleware) string
}

type BaseExtractor struct {
	Config        *tykcommon.MiddlewareIdExtractor
	TykMiddleware *TykMiddleware
	Spec          *APISpec
}

func (e *BaseExtractor) ExtractAndCheck(r *http.Request) (SessionID string, returnOverrides ReturnOverrides) {
	log.WithFields(logrus.Fields{
		"prefix": "idextractor",
	}).Error("This extractor doesn't implement an extraction method, rejecting.")
	return "", ReturnOverrides{403, "Key not authorised"}
}

func (e *BaseExtractor) PostProcess(r *http.Request, thisSessionState SessionState, SessionID string) {
	var sessionLifetime = GetLifetime(e.Spec, &thisSessionState)
	e.Spec.SessionManager.UpdateSession(SessionID, thisSessionState, sessionLifetime)

	context.Set(r, SessionData, thisSessionState)
	context.Set(r, AuthHeaderValue, SessionID)

	return
}

type ValueExtractor struct {
	BaseExtractor
}

type ValueExtractorConfig struct {
	HeaderName string `mapstructure:"header_name" bson:"header_name" json:"header_name"`
	FormParamName string	`mapstructure:"param_name" bson:"param_name" json:"param_name"`
}

func (e *BaseExtractor) GenerateSessionID(input string, mw *TykMiddleware) (SessionID string) {
	data := []byte(input)
	tokenID := fmt.Sprintf("%x", md5.Sum(data))
	SessionID = mw.Spec.OrgID + tokenID
	return SessionID
}


func (e *ValueExtractor) Extract(input interface{}) string {
	headerValue := input.(string)
	return headerValue
}

func (e *ValueExtractor) ExtractAndCheck(r *http.Request) (SessionID string, returnOverrides ReturnOverrides) {
	var extractorOutput string

	var config ValueExtractorConfig
	// TODO: handle this error
	mapstructure.Decode(e.Config.ExtractorConfig, &config)

	switch e.Config.ExtractFrom {
	case tykcommon.HeaderSource:
		var headerName, headerValue string

		// TODO: check if header_name is set
		headerName = e.Config.ExtractorConfig["header_name"].(string)
		headerValue = r.Header.Get(headerName)

		if headerValue == "" {
			log.WithFields(logrus.Fields{
				"path":   r.URL.Path,
				"origin": GetIPFromRequest(r),
			}).Info("Attempted access with malformed header, no auth header found.")

			log.Debug("Looked in: ", headerName)
			log.Debug("Raw data was: ", headerValue)
			log.Debug("Headers are: ", r.Header)

			returnOverrides = ReturnOverrides{
				ResponseCode:  400,
				ResponseError: "Authorization field missing",
			}

			// m.reportLoginFailure(tykId, r)
		}

		// TODO: check if header_name setting exists!
		extractorOutput = r.Header.Get(headerName)
	case tykcommon.FormSource:
		log.Println("Using ValueExtractor with FormSource")
		r.ParseForm()

		if config.FormParamName == "" {
			// No param name, error!
		}

		values := r.Form[config.FormParamName]

		if len(values) > 0 {
			extractorOutput = strings.Join(values, "")
		} else {
			// Error, no value!
		}
	}

	SessionID = e.GenerateSessionID(extractorOutput, e.TykMiddleware)

	log.Println("SessionID", SessionID)

	var keyExists bool
	var previousSessionState SessionState
	previousSessionState, keyExists = e.TykMiddleware.CheckSessionAndIdentityForValidKey(SessionID)

	if keyExists {

		lastUpdated, _ := strconv.Atoi(previousSessionState.LastUpdated)

		deadlineTs := int64(lastUpdated) + previousSessionState.IdExtractorDeadline

		if deadlineTs > time.Now().Unix() {
			e.PostProcess(r, previousSessionState, SessionID)
			returnOverrides = ReturnOverrides{
				ResponseCode: 200,
			}
		}
	}

	return SessionID, returnOverrides
}

type RegexExtractor struct {
	BaseExtractor
}

type RegexExtractorConfig struct {
	HeaderName string `mapstructure:"header_name" bson:"header_name" json:"header_name"`
	RegexExpression string	`mapstructure:"regex_expression" bson:"regex_expression" json:"regex_expression"`
	RegexMatchIndex int	`mapstructure:"regex_match_index" bson:"regex_match_index" json:"regex_match_index"`
}

func (e *RegexExtractor) ExtractAndCheck(r *http.Request) (SessionID string, returnOverrides ReturnOverrides) {
	var extractorOutput string

	var config RegexExtractorConfig
	// TODO: handle this error
	mapstructure.Decode(e.Config.ExtractorConfig, &config)

	// TODO: handle this error: no expression set!
	if e.Config.ExtractorConfig["regex_expression"] == nil {
	}

	expression, err := regexp.Compile(config.RegexExpression)

	if err != nil {
		// TODO: error, the expression is bad!
	}

	switch e.Config.ExtractFrom {
	case tykcommon.HeaderSource:
		var headerName, headerValue string

		// TODO: check if header_name is set
		headerName = e.Config.ExtractorConfig["header_name"].(string)
		headerValue = r.Header.Get(headerName)

		if headerValue == "" {
			log.WithFields(logrus.Fields{
				"path":   r.URL.Path,
				"origin": GetIPFromRequest(r),
			}).Info("Attempted access with malformed header, no auth header found.")

			log.Debug("Looked in: ", headerName)
			log.Debug("Raw data was: ", headerValue)
			log.Debug("Headers are: ", r.Header)

			returnOverrides = ReturnOverrides{
				ResponseCode:  400,
				ResponseError: "Authorization field missing",
			}

			// m.reportLoginFailure(tykId, r)
		}

		// TODO: check if header_name setting exists!
		extractorOutput = r.Header.Get(headerName)
	case tykcommon.BodySource:
		log.Println("Using RegexExtractor with BodySource")
	case tykcommon.FormSource:
		log.Println("Using RegexExtractor with FormSource")
	}

	var regexOutput []string
	regexOutput = expression.FindAllString(extractorOutput, -1)

	SessionID = e.GenerateSessionID(regexOutput[config.RegexMatchIndex], e.TykMiddleware)

	var keyExists bool
	var previousSessionState SessionState
	previousSessionState, keyExists = e.TykMiddleware.CheckSessionAndIdentityForValidKey(SessionID)

	if keyExists {

		lastUpdated, _ := strconv.Atoi(previousSessionState.LastUpdated)

		deadlineTs := int64(lastUpdated) + previousSessionState.IdExtractorDeadline

		if deadlineTs > time.Now().Unix() {
			e.PostProcess(r, previousSessionState, SessionID)
			returnOverrides = ReturnOverrides{
				ResponseCode: 200,
			}
		}
	}

	return SessionID, returnOverrides
}

type XPathExtractor struct {
	BaseExtractor
}

func (e *XPathExtractor) ExtractAndCheck(r *http.Request) (SessionID string, returnOverrides ReturnOverrides) {
	var extractorOutput string

	if e.Config.ExtractorConfig["regex_expression"] == nil {
		// TODO: Error, no expression set!
	}

	var expressionString string
	expressionString = e.Config.ExtractorConfig["regex_expression"].(string)

	expression, err := regexp.Compile(expressionString)

	if err != nil {
		// TODO: error, the expression is bad!
	}

	switch e.Config.ExtractFrom {
	case tykcommon.HeaderSource:
		var headerName, headerValue string

		// TODO: check if header_name is set
		headerName = e.Config.ExtractorConfig["header_name"].(string)
		headerValue = r.Header.Get(headerName)

		if headerValue == "" {
			log.WithFields(logrus.Fields{
				"path":   r.URL.Path,
				"origin": GetIPFromRequest(r),
			}).Info("Attempted access with malformed header, no auth header found.")

			log.Debug("Looked in: ", headerName)
			log.Debug("Raw data was: ", headerValue)
			log.Debug("Headers are: ", r.Header)

			returnOverrides = ReturnOverrides{
				ResponseCode:  400,
				ResponseError: "Authorization field missing",
			}

			// m.reportLoginFailure(tykId, r)
		}

		// TODO: check if header_name setting exists!
		extractorOutput = r.Header.Get(headerName)
	case tykcommon.BodySource:
		log.Println("Using RegexExtractor with BodySource")
	case tykcommon.FormSource:
		log.Println("Using RegexExtractor with FormSource")
	}

	var regexOutput []string
	regexOutput = expression.FindAllString(extractorOutput, -1)

	var matchIndex = 1

	SessionID = e.GenerateSessionID(regexOutput[matchIndex], e.TykMiddleware)

	var keyExists bool
	var previousSessionState SessionState
	previousSessionState, keyExists = e.TykMiddleware.CheckSessionAndIdentityForValidKey(SessionID)

	if keyExists {

		lastUpdated, _ := strconv.Atoi(previousSessionState.LastUpdated)

		deadlineTs := int64(lastUpdated) + previousSessionState.IdExtractorDeadline

		if deadlineTs > time.Now().Unix() {
			e.PostProcess(r, previousSessionState, SessionID)
			returnOverrides = ReturnOverrides{
				ResponseCode: 200,
			}
		}
	}

	return SessionID, returnOverrides
}

func newExtractor(referenceSpec *APISpec, mw *TykMiddleware) {
	var thisExtractor IdExtractor

	baseExtractor := BaseExtractor{&referenceSpec.CustomMiddleware.IdExtractor, mw, referenceSpec}

	// Initialize a extractor based on the API spec.
	switch referenceSpec.CustomMiddleware.IdExtractor.ExtractWith {
	case tykcommon.ValueExtractor:
		thisExtractor = &ValueExtractor{baseExtractor}
	case tykcommon.RegexExtractor:
		thisExtractor = &RegexExtractor{baseExtractor}
	}

	referenceSpec.CustomMiddleware.IdExtractor.Extractor = thisExtractor
}

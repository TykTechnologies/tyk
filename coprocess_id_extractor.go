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
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// IdExtractor is the base interface for an ID extractor.
type IdExtractor interface {
	ExtractAndCheck(*http.Request) (string, ReturnOverrides)
	PostProcess(*http.Request, SessionState, string)
	GenerateSessionID(string, *TykMiddleware) string
}

// BaseExtractor is the base structure for an ID extractor, it implements the IdExtractor interface. Other extractors may override some of its methods.
type BaseExtractor struct {
	Config        *tykcommon.MiddlewareIdExtractor
	TykMiddleware *TykMiddleware
	Spec          *APISpec
}

// ExtractAndCheck is called from the CP middleware, if ID extractor is enabled for the current API.
func (e *BaseExtractor) ExtractAndCheck(r *http.Request) (SessionID string, returnOverrides ReturnOverrides) {
	log.WithFields(logrus.Fields{
		"prefix": "idextractor",
	}).Error("This extractor doesn't implement an extraction method, rejecting.")
	return "", ReturnOverrides{403, "Key not authorised"}
}

// PostProcess sets context variables and updates the storage.
func (e *BaseExtractor) PostProcess(r *http.Request, thisSessionState SessionState, SessionID string) {
	var sessionLifetime = GetLifetime(e.Spec, &thisSessionState)
	e.Spec.SessionManager.UpdateSession(SessionID, thisSessionState, sessionLifetime)

	context.Set(r, SessionData, thisSessionState)
	context.Set(r, AuthHeaderValue, SessionID)

	return
}

// ExtractHeader is used when a HeaderSource is specified.
func (e *BaseExtractor) ExtractHeader(r *http.Request) (headerValue string, err error) {
	var headerName = e.Config.ExtractorConfig["header_name"].(string)
	headerValue = r.Header.Get(headerName)
	if headerValue == "" {
		err = errors.New("Bad header value.")
	}
	return headerValue, err
}

// ExtractForm is used when a FormSource is specified.
func (e *BaseExtractor) ExtractForm(r *http.Request, paramName string) (formValue string, err error) {
	r.ParseForm()
	if paramName == "" {
		// No param name, error?
		err = errors.New("No form param name set")
		return formValue, err
	}

	values := r.Form[paramName]

	if len(values) > 0 {
		formValue = strings.Join(values, "")
	} else {
		// Error, no value!
		err = errors.New("No form value")
	}
	return formValue, err
}

func (e *BaseExtractor) ExtractBody(r *http.Request) (bodyValue string, err error) {
	return bodyValue, err
}

// Error is a helper for logging the extractor errors. It always returns HTTP 400 (so we don't expose any details).
func (e *BaseExtractor) Error(r *http.Request, err error, message string) (returnOverrides ReturnOverrides) {
	log.WithFields(logrus.Fields{
		"path":   r.URL.Path,
		"origin": GetIPFromRequest(r),
	}).Info("Extractor error: ", message, ", ", err)

	return ReturnOverrides{
		ResponseCode:  400,
		ResponseError: "Authorization field missing",
	}
}

// GenerateSessionID is a helper for generating session IDs, it takes an input (usually the extractor output) and a middleware pointer.
func (e *BaseExtractor) GenerateSessionID(input string, mw *TykMiddleware) (SessionID string) {
	data := []byte(input)
	tokenID := fmt.Sprintf("%x", md5.Sum(data))
	SessionID = mw.Spec.OrgID + tokenID
	return SessionID
}

type ValueExtractor struct {
	BaseExtractor
}

type ValueExtractorConfig struct {
	HeaderName    string `mapstructure:"header_name" bson:"header_name" json:"header_name"`
	FormParamName string `mapstructure:"param_name" bson:"param_name" json:"param_name"`
}

func (e *ValueExtractor) Extract(input interface{}) string {
	headerValue := input.(string)
	return headerValue
}

func (e *ValueExtractor) ExtractAndCheck(r *http.Request) (SessionID string, returnOverrides ReturnOverrides) {
	var extractorOutput string
	var err error
	var config ValueExtractorConfig

	err = mapstructure.Decode(e.Config.ExtractorConfig, &config)
	if err != nil {
		returnOverrides = e.Error(r, err, "Couldn't decode ValueExtractor configuration")
		return SessionID, returnOverrides
	}

	switch e.Config.ExtractFrom {
	case tykcommon.HeaderSource:
		extractorOutput, err = e.ExtractHeader(r)
	case tykcommon.FormSource:
		extractorOutput, err = e.ExtractForm(r, config.FormParamName)
	}

	if err != nil {
		returnOverrides = e.Error(r, err, "ValueExtractor error")
		return SessionID, returnOverrides
	}

	SessionID = e.GenerateSessionID(extractorOutput, e.TykMiddleware)

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
	HeaderName      string `mapstructure:"header_name" bson:"header_name" json:"header_name"`
	RegexExpression string `mapstructure:"regex_expression" bson:"regex_expression" json:"regex_expression"`
	RegexMatchIndex int    `mapstructure:"regex_match_index" bson:"regex_match_index" json:"regex_match_index"`
	FormParamName   string `mapstructure:"param_name" bson:"param_name" json:"param_name"`
}

func (e *RegexExtractor) ExtractAndCheck(r *http.Request) (SessionID string, returnOverrides ReturnOverrides) {
	var extractorOutput string
	var err error

	var config RegexExtractorConfig

	err = mapstructure.Decode(e.Config.ExtractorConfig, &config)

	if err != nil {
		returnOverrides = e.Error(r, err, "Can't decode RegexExtractor configuration")
		return SessionID, returnOverrides
	}

	if e.Config.ExtractorConfig["regex_expression"] == nil {
		returnOverrides = e.Error(r, nil, "RegexExtractor expects an expression")
		return SessionID, returnOverrides
	}

	var expression *regexp.Regexp
	expression, err = regexp.Compile(config.RegexExpression)

	if err != nil {
		returnOverrides = e.Error(r, nil, "RegexExtractor found an invalid expression")
		return SessionID, returnOverrides
	}

	switch e.Config.ExtractFrom {
	case tykcommon.HeaderSource:
		extractorOutput, err = e.ExtractHeader(r)
	case tykcommon.BodySource:
		extractorOutput, err = e.ExtractBody(r)
	case tykcommon.FormSource:
		extractorOutput, err = e.ExtractForm(r, config.FormParamName)
	}

	if err != nil {
		returnOverrides = e.Error(r, err, "RegexExtractor error")
		return SessionID, returnOverrides
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

// newExtractor is called from the CP middleware for every API that specifies extractor settings.
func newExtractor(referenceSpec *APISpec, mw *TykMiddleware) {
	var thisExtractor IdExtractor

	baseExtractor := BaseExtractor{&referenceSpec.CustomMiddleware.IdExtractor, mw, referenceSpec}

	// Initialize a extractor based on the API spec.
	switch referenceSpec.CustomMiddleware.IdExtractor.ExtractWith {
	case tykcommon.ValueExtractor:
		thisExtractor = &ValueExtractor{baseExtractor}
	case tykcommon.RegexExtractor:
		thisExtractor = &RegexExtractor{baseExtractor}
	case tykcommon.XPathExtractor:
		thisExtractor = &XPathExtractor{baseExtractor}
	}

	referenceSpec.CustomMiddleware.IdExtractor.Extractor = thisExtractor
}

// +build coprocess

package main

import (
	"crypto/md5"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/mitchellh/mapstructure"
	"gopkg.in/xmlpath.v2"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"
)

// IdExtractor is the base interface for an ID extractor.
type IdExtractor interface {
	ExtractAndCheck(*http.Request) (string, ReturnOverrides)
	PostProcess(*http.Request, *user.SessionState, string)
	GenerateSessionID(string, BaseMiddleware) string
}

// BaseExtractor is the base structure for an ID extractor, it implements the IdExtractor interface. Other extractors may override some of its methods.
type BaseExtractor struct {
	Config  *apidef.MiddlewareIdExtractor
	BaseMid BaseMiddleware
	Spec    *APISpec
}

// ExtractAndCheck is called from the CP middleware, if ID extractor is enabled for the current API.
func (e *BaseExtractor) ExtractAndCheck(r *http.Request) (sessionID string, returnOverrides ReturnOverrides) {
	log.WithFields(logrus.Fields{
		"prefix": "idextractor",
	}).Error("This extractor doesn't implement an extraction method, rejecting.")
	return "", ReturnOverrides{ResponseCode: 403, ResponseError: "Key not authorised"}
}

// PostProcess sets context variables and updates the storage.
func (e *BaseExtractor) PostProcess(r *http.Request, session *user.SessionState, sessionID string) {
	sessionLifetime := session.Lifetime(e.Spec.SessionLifetime)
	e.Spec.SessionManager.UpdateSession(sessionID, session, sessionLifetime, false)

	ctxSetSession(r, session)
	ctxSetAuthToken(r, sessionID)
}

// ExtractHeader is used when a HeaderSource is specified.
func (e *BaseExtractor) ExtractHeader(r *http.Request) (headerValue string, err error) {
	headerName := e.Config.ExtractorConfig["header_name"].(string)
	headerValue = r.Header.Get(headerName)
	if headerValue == "" {
		err = errors.New("Bad header value.")
	}
	return headerValue, err
}

// ExtractForm is used when a FormSource is specified.
func (e *BaseExtractor) ExtractForm(r *http.Request, paramName string) (formValue string, err error) {
	copiedRequest := copyRequest(r)
	copiedRequest.ParseForm()

	if paramName == "" {
		return "", errors.New("no form param name set")
	}

	values := copiedRequest.Form[paramName]
	if len(values) == 0 {
		return "", errors.New("no form value")
	}

	return strings.Join(values, ""), nil
}

func (e *BaseExtractor) ExtractBody(r *http.Request) (bodyValue string, err error) {
	return bodyValue, err
}

// Error is a helper for logging the extractor errors. It always returns HTTP 400 (so we don't expose any details).
func (e *BaseExtractor) Error(r *http.Request, err error, message string) (returnOverrides ReturnOverrides) {
	logEntry := getLogEntryForRequest(r, "", nil)
	logEntry.Info("Extractor error: ", message, ", ", err)

	return ReturnOverrides{
		ResponseCode:  400,
		ResponseError: "Authorization field missing",
	}
}

// GenerateSessionID is a helper for generating session IDs, it takes an input (usually the extractor output) and a middleware pointer.
func (e *BaseExtractor) GenerateSessionID(input string, mw BaseMiddleware) (sessionID string) {
	data := []byte(input)
	tokenID := fmt.Sprintf("%x", md5.Sum(data))
	sessionID = mw.Spec.OrgID + tokenID
	return sessionID
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

func (e *ValueExtractor) ExtractAndCheck(r *http.Request) (sessionID string, returnOverrides ReturnOverrides) {
	var extractorOutput string
	var config ValueExtractorConfig

	err := mapstructure.Decode(e.Config.ExtractorConfig, &config)
	if err != nil {
		returnOverrides = e.Error(r, err, "Couldn't decode ValueExtractor configuration")
		return sessionID, returnOverrides
	}

	switch e.Config.ExtractFrom {
	case apidef.HeaderSource:
		extractorOutput, err = e.ExtractHeader(r)
	case apidef.FormSource:
		extractorOutput, err = e.ExtractForm(r, config.FormParamName)
	}

	if err != nil {
		returnOverrides = e.Error(r, err, "ValueExtractor error")
		return sessionID, returnOverrides
	}

	sessionID = e.GenerateSessionID(extractorOutput, e.BaseMid)

	previousSession, keyExists := e.BaseMid.CheckSessionAndIdentityForValidKey(sessionID)

	if keyExists {
		if previousSession.IdExtractorDeadline > time.Now().Unix() {
			e.PostProcess(r, &previousSession, sessionID)
			returnOverrides = ReturnOverrides{
				ResponseCode: 200,
			}
		}
	}

	return sessionID, returnOverrides
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
	var config RegexExtractorConfig

	err := mapstructure.Decode(e.Config.ExtractorConfig, &config)
	if err != nil {
		returnOverrides = e.Error(r, err, "Can't decode RegexExtractor configuration")
		return SessionID, returnOverrides
	}

	if e.Config.ExtractorConfig["regex_expression"] == nil {
		returnOverrides = e.Error(r, nil, "RegexExtractor expects an expression")
		return SessionID, returnOverrides
	}

	expression, err := regexp.Compile(config.RegexExpression)

	if err != nil {
		returnOverrides = e.Error(r, nil, "RegexExtractor found an invalid expression")
		return SessionID, returnOverrides
	}

	switch e.Config.ExtractFrom {
	case apidef.HeaderSource:
		extractorOutput, err = e.ExtractHeader(r)
	case apidef.BodySource:
		extractorOutput, err = e.ExtractBody(r)
	case apidef.FormSource:
		extractorOutput, err = e.ExtractForm(r, config.FormParamName)
	}

	if err != nil {
		returnOverrides = e.Error(r, err, "RegexExtractor error")
		return SessionID, returnOverrides
	}

	regexOutput := expression.FindAllString(extractorOutput, -1)

	if config.RegexMatchIndex > len(regexOutput)-1 {
		returnOverrides = e.Error(r, fmt.Errorf("Can't find regexp match group"), "RegexExtractor error")
		return SessionID, returnOverrides
	}

	SessionID = e.GenerateSessionID(regexOutput[config.RegexMatchIndex], e.BaseMid)

	previousSession, keyExists := e.BaseMid.CheckSessionAndIdentityForValidKey(SessionID)

	if keyExists {

		if previousSession.IdExtractorDeadline > time.Now().Unix() {
			e.PostProcess(r, &previousSession, SessionID)
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

type XPathExtractorConfig struct {
	HeaderName      string `mapstructure:"header_name" bson:"header_name" json:"header_name"`
	RegexExpression string `mapstructure:"regex_expression" bson:"regex_expression" json:"regex_expression"`
	RegexMatchIndex int    `mapstructure:"regex_match_index" bson:"regex_match_index" json:"regex_match_index"`
	FormParamName   string `mapstructure:"param_name" bson:"param_name" json:"param_name"`
}

func (e *XPathExtractor) ExtractAndCheck(r *http.Request) (SessionID string, returnOverrides ReturnOverrides) {
	var extractorOutput string

	var config XPathExtractorConfig
	err := mapstructure.Decode(e.Config.ExtractorConfig, &config)

	if e.Config.ExtractorConfig["xpath_expression"] == nil {
		returnOverrides = e.Error(r, err, "XPathExtractor: no expression set")
		return SessionID, returnOverrides
	}

	expressionString := e.Config.ExtractorConfig["xpath_expression"].(string)

	expression, err := xmlpath.Compile(expressionString)
	if err != nil {
		returnOverrides = e.Error(r, err, "XPathExtractor: bad expression")
		return SessionID, returnOverrides
	}

	switch e.Config.ExtractFrom {
	case apidef.HeaderSource:
		extractorOutput, err = e.ExtractHeader(r)
	case apidef.BodySource:
		extractorOutput, err = e.ExtractBody(r)
	case apidef.FormSource:
		extractorOutput, err = e.ExtractForm(r, config.FormParamName)
	}
	if err != nil {
		returnOverrides = e.Error(r, err, "XPathExtractor error")
		return SessionID, returnOverrides
	}

	extractedXml, err := xmlpath.Parse(strings.NewReader(extractorOutput))
	if err != nil {
		returnOverrides = e.Error(r, err, "XPathExtractor: couldn't parse input")
		return SessionID, returnOverrides
	}

	output, ok := expression.String(extractedXml)
	if !ok {
		returnOverrides = e.Error(r, err, "XPathExtractor: no input")
		return SessionID, returnOverrides
	}

	SessionID = e.GenerateSessionID(output, e.BaseMid)

	previousSession, keyExists := e.BaseMid.CheckSessionAndIdentityForValidKey(SessionID)
	if keyExists {
		if previousSession.IdExtractorDeadline > time.Now().Unix() {
			e.PostProcess(r, &previousSession, SessionID)
			returnOverrides = ReturnOverrides{
				ResponseCode: 200,
			}
		}
	}

	return SessionID, returnOverrides
}

// newExtractor is called from the CP middleware for every API that specifies extractor settings.
func newExtractor(referenceSpec *APISpec, mw BaseMiddleware) {
	var extractor IdExtractor

	baseExtractor := BaseExtractor{&referenceSpec.CustomMiddleware.IdExtractor, mw, referenceSpec}

	// Initialize a extractor based on the API spec.
	switch referenceSpec.CustomMiddleware.IdExtractor.ExtractWith {
	case apidef.ValueExtractor:
		extractor = &ValueExtractor{baseExtractor}
	case apidef.RegexExtractor:
		extractor = &RegexExtractor{baseExtractor}
	case apidef.XPathExtractor:
		extractor = &XPathExtractor{baseExtractor}
	}

	referenceSpec.CustomMiddleware.IdExtractor.Extractor = extractor
}

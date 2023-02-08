package gateway

import (
	"crypto/md5"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
	xmlpath "gopkg.in/xmlpath.v2"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/regexp"
)

// IdExtractor is the base interface for an ID extractor.
type IdExtractor interface {
	ExtractAndCheck(*http.Request) (string, ReturnOverrides)
	GenerateSessionID(string, BaseMiddleware) string
}

// BaseExtractor is the base structure for an ID extractor, it implements the IdExtractor interface. Other extractors may override some of its methods.
type BaseExtractor struct {
	Config *apidef.MiddlewareIdExtractor
	BaseMiddleware
	Spec *APISpec
}

// ExtractAndCheck is called from the CP middleware, if ID extractor is enabled for the current API.
func (e *BaseExtractor) ExtractAndCheck(r *http.Request) (sessionID string, returnOverrides ReturnOverrides) {
	log.WithFields(logrus.Fields{
		"prefix": "idextractor",
	}).Error("This extractor doesn't implement an extraction method, rejecting.")
	return "", ReturnOverrides{ResponseCode: 403, ResponseError: "Key not authorised"}
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
	parseForm(r)

	if paramName == "" {
		return "", errors.New("no form param name set")
	}

	values := r.Form[paramName]
	if len(values) == 0 {
		return "", errors.New("no form value")
	}

	return strings.Join(values, ""), nil
}

// ExtractBody is used when BodySource is specified.
func (e *BaseExtractor) ExtractBody(r *http.Request) (string, error) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return "", err
	}
	return string(body), err
}

// Error is a helper for logging the extractor errors. It always returns HTTP 400 (so we don't expose any details).
func (e *BaseExtractor) Error(r *http.Request, err error, message string) (returnOverrides ReturnOverrides) {
	logEntry := e.Gw.getLogEntryForRequest(e.Logger(), r, "", nil)
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
	sessionID = e.Gw.generateToken(mw.Spec.OrgID, tokenID)
	return sessionID
}

type ValueExtractor struct {
	BaseExtractor
	cfg *ValueExtractorConfig
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
	if e.cfg == nil {
		config := &ValueExtractorConfig{}
		if err := mapstructure.Decode(e.Config.ExtractorConfig, config); err != nil {
			returnOverrides = e.Error(r, err, "Couldn't decode ValueExtractor configuration")
			return sessionID, returnOverrides
		}
		e.cfg = config
	}

	var extractorOutput string
	var err error
	switch e.Config.ExtractFrom {
	case apidef.HeaderSource:
		extractorOutput, err = e.ExtractHeader(r)
	case apidef.FormSource:
		extractorOutput, err = e.ExtractForm(r, e.cfg.FormParamName)
	}

	if err != nil {
		returnOverrides = e.Error(r, err, "ValueExtractor error")
		return sessionID, returnOverrides
	}

	sessionID = e.GenerateSessionID(extractorOutput, e.BaseMiddleware)
	previousSession, keyExists := e.CheckSessionAndIdentityForValidKey(sessionID, r)
	sessionID = previousSession.KeyID

	if keyExists {
		if previousSession.IdExtractorDeadline > time.Now().Unix() {
			ctxSetSession(r, &previousSession, true, e.Gw.GetConfig().HashKeys)
			returnOverrides = ReturnOverrides{
				ResponseCode: 200,
			}
		}
	}

	return sessionID, returnOverrides
}

type RegexExtractor struct {
	BaseExtractor
	compiledExpr *regexp.Regexp
	cfg          *RegexExtractorConfig
}

type RegexExtractorConfig struct {
	HeaderName      string `mapstructure:"header_name" bson:"header_name" json:"header_name"`
	RegexExpression string `mapstructure:"regex_expression" bson:"regex_expression" json:"regex_expression"`
	RegexMatchIndex int    `mapstructure:"regex_match_index" bson:"regex_match_index" json:"regex_match_index"`
	FormParamName   string `mapstructure:"param_name" bson:"param_name" json:"param_name"`
}

func (e *RegexExtractor) ExtractAndCheck(r *http.Request) (SessionID string, returnOverrides ReturnOverrides) {
	// Parse specific configuration settings:
	if e.cfg == nil {
		config := &RegexExtractorConfig{}
		if err := mapstructure.Decode(e.Config.ExtractorConfig, config); err != nil {
			returnOverrides = e.Error(r, err, "Can't decode RegexExtractor configuration")
			return SessionID, returnOverrides
		}
		e.cfg = config
	}

	if e.Config.ExtractorConfig["regex_expression"] == nil {
		returnOverrides = e.Error(r, nil, "RegexExtractor expects an expression")
		return SessionID, returnOverrides
	}

	var err error
	if e.compiledExpr == nil {
		e.compiledExpr, err = regexp.Compile(e.cfg.RegexExpression)
		if err != nil {
			returnOverrides = e.Error(r, nil, "RegexExtractor found an invalid expression")
			return SessionID, returnOverrides
		}
	}

	var extractorOutput string
	switch e.Config.ExtractFrom {
	case apidef.HeaderSource:
		extractorOutput, err = e.ExtractHeader(r)
	case apidef.BodySource:
		extractorOutput, err = e.ExtractBody(r)
	case apidef.FormSource:
		extractorOutput, err = e.ExtractForm(r, e.cfg.FormParamName)
	}
	if err != nil {
		returnOverrides = e.Error(r, err, "RegexExtractor error")
		return SessionID, returnOverrides
	}

	regexOutput := e.compiledExpr.FindAllString(extractorOutput, -1)
	if e.cfg.RegexMatchIndex > len(regexOutput)-1 {
		returnOverrides = e.Error(r, fmt.Errorf("Can't find regexp match group"), "RegexExtractor error")
		return SessionID, returnOverrides
	}

	SessionID = e.GenerateSessionID(regexOutput[e.cfg.RegexMatchIndex], e.BaseMiddleware)
	previousSession, keyExists := e.BaseMiddleware.CheckSessionAndIdentityForValidKey(SessionID, r)
	SessionID = previousSession.KeyID

	if keyExists {
		if previousSession.IdExtractorDeadline > time.Now().Unix() {
			ctxSetSession(r, &previousSession, true, e.Gw.GetConfig().HashKeys)
			returnOverrides = ReturnOverrides{
				ResponseCode: 200,
			}
		}
	}
	return SessionID, returnOverrides
}

type XPathExtractor struct {
	BaseExtractor
	cfg  *XPathExtractorConfig
	path *xmlpath.Path
}

type XPathExtractorConfig struct {
	HeaderName      string `mapstructure:"header_name" bson:"header_name" json:"header_name"`
	RegexExpression string `mapstructure:"regex_expression" bson:"regex_expression" json:"regex_expression"`
	RegexMatchIndex int    `mapstructure:"regex_match_index" bson:"regex_match_index" json:"regex_match_index"`
	FormParamName   string `mapstructure:"param_name" bson:"param_name" json:"param_name"`
}

func (e *XPathExtractor) ExtractAndCheck(r *http.Request) (SessionID string, returnOverrides ReturnOverrides) {
	var err error
	config := &XPathExtractorConfig{}
	if err = mapstructure.Decode(e.Config.ExtractorConfig, config); err != nil {
		returnOverrides = e.Error(r, err, "Can't decode XPathExtractor configuration")
		return SessionID, returnOverrides
	}
	e.cfg = config
	if e.Config.ExtractorConfig["xpath_expression"] == nil {
		returnOverrides = e.Error(r, err, "XPathExtractor: no expression set")
		return SessionID, returnOverrides
	}

	if e.path == nil {
		expressionString := e.Config.ExtractorConfig["xpath_expression"].(string)
		e.path, err = xmlpath.Compile(expressionString)
		if err != nil {
			returnOverrides = e.Error(r, err, "XPathExtractor: bad expression")
			return SessionID, returnOverrides
		}
	}

	var extractorOutput string
	switch e.Config.ExtractFrom {
	case apidef.HeaderSource:
		extractorOutput, err = e.ExtractHeader(r)
	case apidef.BodySource:
		extractorOutput, err = e.ExtractBody(r)
	case apidef.FormSource:
		extractorOutput, err = e.ExtractForm(r, e.cfg.FormParamName)
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

	output, ok := e.path.String(extractedXml)
	if !ok {
		returnOverrides = e.Error(r, err, "XPathExtractor: no input")
		return SessionID, returnOverrides
	}

	SessionID = e.GenerateSessionID(output, e.BaseMiddleware)
	previousSession, keyExists := e.BaseMiddleware.CheckSessionAndIdentityForValidKey(SessionID, r)
	SessionID = previousSession.KeyID

	if keyExists {
		if previousSession.IdExtractorDeadline > time.Now().Unix() {
			ctxSetSession(r, &previousSession, true, e.Gw.GetConfig().HashKeys)
			returnOverrides = ReturnOverrides{
				ResponseCode: 200,
			}
		}
	}

	return SessionID, returnOverrides
}

// newExtractor is called from the CP middleware for every API that specifies extractor settings.
func newExtractor(referenceSpec *APISpec, mw BaseMiddleware) {
	if referenceSpec.CustomMiddleware.IdExtractor.Disabled {
		return
	}

	var extractor IdExtractor

	baseExtractor := BaseExtractor{&referenceSpec.CustomMiddleware.IdExtractor, mw, referenceSpec}

	// Initialize a extractor based on the API spec.
	switch referenceSpec.CustomMiddleware.IdExtractor.ExtractWith {
	case apidef.ValueExtractor:
		extractor = &ValueExtractor{baseExtractor, nil}
	case apidef.RegexExtractor:
		extractor = &RegexExtractor{baseExtractor, nil, nil}
	case apidef.XPathExtractor:
		extractor = &XPathExtractor{baseExtractor, nil, nil}
	}

	referenceSpec.CustomMiddleware.IdExtractor.Extractor = extractor
}

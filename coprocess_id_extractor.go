// +build coprocess

package main

import (
	"github.com/Sirupsen/logrus"
	"github.com/TykTechnologies/tykcommon"
	"github.com/gorilla/context"
	// "gopkg.in/xmlpath.v2"
	"regexp"

	"crypto/md5"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

type IdExtractor interface {
	ExtractAndCheck(*http.Request) (string, ReturnOverrides)
	PostProcess(*http.Request, SessionState, string)
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

	e.Spec.SessionManager.UpdateSession(SessionID, thisSessionState, e.Spec.APIDefinition.SessionLifetime)

	context.Set(r, SessionData, thisSessionState)
	context.Set(r, AuthHeaderValue, SessionID)

	return
}

type ValueExtractor struct {
	BaseExtractor
}


func (e *ValueExtractor) Extract(input interface{}) string {
	headerValue := input.(string)
	return headerValue
}

func (e *ValueExtractor) ExtractAndCheck(r *http.Request) (SessionID string, returnOverrides ReturnOverrides) {
	var extractorOutput, tokenID string

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
	}

	// Prepare a session ID.
	data := []byte(extractorOutput)
	tokenID = fmt.Sprintf("%x", md5.Sum(data))
	SessionID = e.TykMiddleware.Spec.OrgID + tokenID

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

func (e *RegexExtractor) ExtractAndCheck(r *http.Request) (SessionID string, returnOverrides ReturnOverrides) {
	var extractorOutput, tokenID string

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
	}

	var regexOutput []string
	regexOutput = expression.FindAllString(extractorOutput, -1)

	var matchIndex = 1

	// Prepare a session ID.
	data := []byte(regexOutput[1])
	tokenID = fmt.Sprintf("%x", md5.Sum(data))
	SessionID = e.TykMiddleware.Spec.OrgID + tokenID

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

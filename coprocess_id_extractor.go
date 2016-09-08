// +build coprocess

package main

import (
	"github.com/Sirupsen/logrus"
	"github.com/gorilla/context"
	"github.com/TykTechnologies/tykcommon"

	"crypto/md5"
	"net/http"
	"fmt"
)

type IdExtractor interface {
	ExtractAndCheck(*http.Request, *SessionState) (string, ReturnOverrides)
	PostProcess(*http.Request, SessionState, string)
}

type ValueExtractor struct {
	Config *tykcommon.MiddlewareIdExtractor
	TykMiddleware *TykMiddleware
	Spec *APISpec
}

func(e *ValueExtractor) Extract(input interface{}) string {
	headerValue := input.(string)
	return headerValue
}

func(e *ValueExtractor) PostProcess(r *http.Request, thisSessionState SessionState, SessionID string) {

	e.Spec.SessionManager.UpdateSession(SessionID, thisSessionState, e.Spec.APIDefinition.SessionLifetime)

	context.Set(r, SessionData, thisSessionState)
	context.Set(r, AuthHeaderValue, SessionID)

	return
}

func(e *ValueExtractor) ExtractAndCheck(r *http.Request, thisSessionState *SessionState) (SessionID string, returnOverrides ReturnOverrides) {
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
				ResponseCode: 400,
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
		e.PostProcess(r, previousSessionState, SessionID)
		returnOverrides = ReturnOverrides{
			ResponseCode: 200,
		}
	}

	return SessionID, returnOverrides
}

func newExtractor(referenceSpec *APISpec, mw *TykMiddleware) {
	var thisExtractor IdExtractor

	// Initialize a extractor based on the API spec.
	switch referenceSpec.CustomMiddleware.IdExtractor.ExtractWith {
	case tykcommon.ValueExtractor:
		thisExtractor = &ValueExtractor{ &referenceSpec.CustomMiddleware.IdExtractor, mw, referenceSpec}
	}

	referenceSpec.CustomMiddleware.IdExtractor.Extractor = thisExtractor
}

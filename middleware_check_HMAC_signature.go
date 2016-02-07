package main

import "net/http"

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"github.com/Sirupsen/logrus"
	"github.com/gorilla/context"
	"math"
	"net/url"
	"sort"
	"strings"
	"time"
)

// TODO: change these to real values
const DateHeaderSpec string = "Date"
const AltHeaderSpec string = "x-aux-date"
const HMACClockSkewLimitInMs float64 = 1000

// HMACMiddleware will check if the request has a signature, and if the request is allowed through
type HMACMiddleware struct {
	*TykMiddleware
}

func (hm *HMACMiddleware) authorizationError(w http.ResponseWriter, r *http.Request) (error, int) {
	log.WithFields(logrus.Fields{
		"prefix": "hmac",
	}).WithFields(logrus.Fields{
		"path":   r.URL.Path,
		"origin": GetIPFromRequest(r),
	}).Info("Authorization field missing or malformed")

	return errors.New("Authorization field missing, malformed or invalid"), 400
}

// New lets you do any initialisations for the object can be done here
func (hm *HMACMiddleware) New() {}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (hm *HMACMiddleware) GetConfig() (interface{}, error) {
	return nil, nil
}

func (hm *HMACMiddleware) getDateHeader(r *http.Request) (string, bool) {

	auxHeaderVal := r.Header.Get(AltHeaderSpec)
	dateHeaderVal := r.Header.Get(DateHeaderSpec)

	// Prefer aux if present
	if auxHeaderVal != "" {
		authHeaderValue := r.Header.Get("Authorization")
		log.WithFields(logrus.Fields{
			"prefix":      "hmac",
			"auth_header": authHeaderValue,
		}).Warning("Using auxiliary header for this request")
		return auxHeaderVal, true
	}

	if dateHeaderVal != "" {
		log.WithFields(logrus.Fields{
			"prefix": "hmac",
		}).Debug("Got auth header")
		return dateHeaderVal, false
	}

	return "", false
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (hm *HMACMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	log.WithFields(logrus.Fields{
		"prefix": "hmac",
	}).Debug("HMAC middleware activated")

	authHeaderValue := r.Header.Get("Authorization")
	if authHeaderValue == "" {
		return hm.authorizationError(w, r)
	}

	log.WithFields(logrus.Fields{
		"prefix": "hmac",
	}).Debug("Got auth header")
	DateHeaderVal, _ := hm.getDateHeader(r)
	if DateHeaderVal == "" {
		return hm.authorizationError(w, r)
	}

	isOutOftime := hm.checkClockSkew(DateHeaderVal)
	if isOutOftime == false {
		log.WithFields(logrus.Fields{
			"prefix": "hmac",
			"path":   r.URL.Path,
			"origin": GetIPFromRequest(r),
		}).Warning("Date is out of allowed range.")

		handler := ErrorHandler{hm.TykMiddleware}
		handler.HandleError(w, r, "Date is out of allowed range.", 400)
		return errors.New("Date is out of allowed range."), 400
	}

	log.WithFields(logrus.Fields{
		"prefix": "hmac",
	}).Debug("Got date")

	// Extract the keyId:
	splitTypes := strings.Split(authHeaderValue, " ")
	if len(splitTypes) != 2 {
		return hm.authorizationError(w, r)
	}

	log.WithFields(logrus.Fields{
		"prefix": "hmac",
	}).Debug("Found two fields")

	if strings.ToLower(splitTypes[0]) != "signature" {
		return hm.authorizationError(w, r)
	}

	log.WithFields(logrus.Fields{
		"prefix": "hmac",
	}).Debug("Found signature value field")

	splitValues := strings.Split(splitTypes[1], ",")
	if len(splitValues) != 3 {
		log.WithFields(logrus.Fields{
			"prefix": "hmac",
		}).Debug("Comma length is wrong - got: ", splitValues)
		return hm.authorizationError(w, r)
	}

	log.WithFields(logrus.Fields{
		"prefix": "hmac",
	}).Debug("Found 2 commas - getting elements of signature")

	// extract the keyId, algorithm and signature
	keyId := ""
	algorithm := ""
	signature := ""
	for _, v := range splitValues {
		splitKeyValuePair := strings.Split(v, "=")

		if len(splitKeyValuePair) != 2 {
			log.WithFields(logrus.Fields{
				"prefix": "hmac",
			}).Info("Equals length is wrong - got: ", splitKeyValuePair)
			return hm.authorizationError(w, r)
		}
		if strings.ToLower(splitKeyValuePair[0]) == "keyid" {
			keyId = strings.Trim(splitKeyValuePair[1], "\"")
		}
		if strings.ToLower(splitKeyValuePair[0]) == "algorithm" {
			algorithm = strings.Trim(splitKeyValuePair[1], "\"")
		}
		if strings.ToLower(splitKeyValuePair[0]) == "signature" {
			combinedSig := strings.Join(splitKeyValuePair[1:], "")
			signature = strings.Trim(combinedSig, "\"")
		}
	}

	log.WithFields(logrus.Fields{
		"prefix": "hmac",
	}).Debug("Extracted values... checking validity")

	// None may be empty
	if keyId == "" || algorithm == "" || signature == "" {
		return hm.authorizationError(w, r)
	}

	log.WithFields(logrus.Fields{
		"prefix": "hmac",
	}).Debug("Key is valid: ", keyId)
	log.WithFields(logrus.Fields{
		"prefix": "hmac",
	}).Debug("algo is valid: ", algorithm)
	log.WithFields(logrus.Fields{
		"prefix": "hmac",
	}).Debug("signature isn't empty: ", signature)

	// Check if API key valid
	thisSessionState, keyExists := hm.TykMiddleware.CheckSessionAndIdentityForValidKey(keyId)
	if !keyExists {
		return hm.authorizationError(w, r)
	}

	log.WithFields(logrus.Fields{
		"prefix": "hmac",
	}).Debug("Found key in session store")

	// Set session state on context, we will need it later
	context.Set(r, SessionData, thisSessionState)
	context.Set(r, AuthHeaderValue, keyId)

	if thisSessionState.HmacSecret == "" || thisSessionState.HMACEnabled == false {
		log.WithFields(logrus.Fields{
			"prefix": "hmac",
			"path":   r.URL.Path,
			"origin": GetIPFromRequest(r),
		}).Info("API Requires HMAC signature, session missing HMACSecret or HMAC not enabled for key")

		return errors.New("This key is invalid"), 400
	}

	log.WithFields(logrus.Fields{
		"prefix": "hmac",
	}).Debug("Sessionstate is HMAC enabled")

	ourSignature := hm.generateSignatureFromRequest(r, thisSessionState.HmacSecret)
	log.WithFields(logrus.Fields{
		"prefix": "hmac",
	}).Debug("Our Signature: ", ourSignature)

	compareTo, err := url.QueryUnescape(signature)

	if err != nil {
		return hm.authorizationError(w, r)
	}

	log.WithFields(logrus.Fields{
		"prefix": "hmac",
	}).Debug("Request Signature: ", compareTo)

	log.WithFields(logrus.Fields{
		"prefix": "hmac",
	}).Debug("Should be: ", ourSignature)

	if ourSignature != compareTo {
		log.WithFields(logrus.Fields{
			"prefix": "hmac",
			"path":   r.URL.Path,
			"origin": GetIPFromRequest(r),
		}).Info("Request signature is invalid")

		// Fire Authfailed Event
		AuthFailed(hm.TykMiddleware, r, keyId)
		// Report in health check
		ReportHealthCheckValue(hm.Spec.Health, KeyFailure, "-1")

		return errors.New("Request signature is invalid"), 400
	}

	log.WithFields(logrus.Fields{
		"prefix": "hmac",
	}).Debug("Signature matches")

	// Everything seems in order let the request through
	return nil, 200
}

func (hm HMACMiddleware) parseFormParams(values url.Values) string {
	kvValues := map[string]string{}
	keys := []string{}

	log.WithFields(logrus.Fields{
		"prefix": "hmac",
	}).Debug("Parsing header values")

	for k, v := range values {
		log.WithFields(logrus.Fields{
			"prefix": "hmac",
		}).Debug("Form parser - processing key: ", k)
		log.WithFields(logrus.Fields{
			"prefix": "hmac",
		}).Debug("Form parser - processing value: ", v)
		encodedKey := url.QueryEscape(k)
		encodedVals := []string{}
		for _, raw_value := range v {
			encodedVals = append(encodedVals, url.QueryEscape(raw_value))
		}
		joined_vals := strings.Join(encodedVals, "|")
		kvPair := encodedKey + "=" + joined_vals
		kvValues[k] = kvPair
		keys = append(keys, k)
	}

	// sort the keys in alphabetical order
	sort.Strings(keys)
	sortedKvs := []string{}

	// Put the prepared key value params in order according to above sort
	for _, sk := range keys {
		sortedKvs = append(sortedKvs, kvValues[sk])
	}

	// Join the kv's up as per spec
	prepared_params := strings.Join(sortedKvs, "&")

	return prepared_params
}

// Generates our signature - based on: https://web-payments.org/specs/ED/http-signatures/2014-02-01/#page-3 HMAC signing
func (hm HMACMiddleware) generateSignatureFromRequest(r *http.Request, secret string) string {
	//method := strings.ToUpper(r.Method)
	//base_url := url.QueryEscape(r.URL.RequestURI())

	headerVal, useAlt := hm.getDateHeader(r)
	date_header := url.QueryEscape(headerVal)

	// Not using form params for now, just date string
	//params := url.QueryEscape(hm.parseFormParams(r.Form))

	spec := DateHeaderSpec
	if useAlt {
		spec = AltHeaderSpec
	}

	// Prep the signature string
	signatureString := strings.ToLower(spec) + ":" + date_header

	log.WithFields(logrus.Fields{
		"prefix": "hmac",
	}).Debug("Signature string before encoding: ", signatureString)

	// Encode it
	key := []byte(secret)
	h := hmac.New(sha1.New, key)
	h.Write([]byte(signatureString))

	encodedString := base64.StdEncoding.EncodeToString(h.Sum(nil))
	log.WithFields(logrus.Fields{
		"prefix": "hmac",
	}).Debug("Encoded signature string: ", encodedString)

	log.WithFields(logrus.Fields{
		"prefix": "hmac",
	}).Debug("URL Encoded: ", url.QueryEscape(encodedString))

	// Return as base64
	return encodedString
}

func (hm HMACMiddleware) checkClockSkew(dateHeaderValue string) bool {
	// Reference layout for parsing time: "Mon Jan 2 15:04:05 MST 2006"

	refDate := "Mon, 02 Jan 2006 15:04:05 MST"

	tim, err := time.Parse(refDate, dateHeaderValue)

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix":      "hmac",
			"date_string": tim,
		}).Error("Date parsing failed")
		return false
	}

	inSec := tim.UnixNano()
	now := time.Now().UnixNano()

	diff := now - inSec

	in_ms := diff / 1000000

	if hm.TykMiddleware.Spec.HmacAllowedClockSkew <= 0 {
		return true
	}

	if math.Abs(float64(in_ms)) > hm.TykMiddleware.Spec.HmacAllowedClockSkew {
		log.WithFields(logrus.Fields{
			"prefix": "hmac",
		}).Debug("Difference is: ", math.Abs(float64(in_ms)))
		return false
	}

	return true
}

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

// Test key: 53ac07777cbb8c2d530000021a42331a43bd45555d5c923bdb36fc8a

// TODO: change these to real values
const DateHeaderSpec string = "Date"
const HMACClockSkewLimitInMs float64 = 300

// HMACMiddleware will check if the request has a signature, and if the request is allowed through
type HMACMiddleware struct {
	TykMiddleware
}

func (hm *HMACMiddleware) authorizationError(w http.ResponseWriter, r *http.Request) (error, int) {
	log.WithFields(logrus.Fields{
		"path":   r.URL.Path,
		"origin": r.RemoteAddr,
	}).Info("Authorization field missing or malformed")

	return errors.New("Authorization field missing, malformed or invalid"), 400
}

// New lets you do any initialisations for the object can be done here
func (hm *HMACMiddleware) New() {}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (hm *HMACMiddleware) GetConfig() (interface{}, error) {
	return nil, nil
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (hm *HMACMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	log.Debug("HMAC middleware activated")

	authHeaderValue := r.Header.Get("Authorization")
	if authHeaderValue == "" {
		return hm.authorizationError(w, r)
	}

	log.Debug("Got auth header")

	if r.Header.Get(DateHeaderSpec) == "" {
		log.Debug("Date missing")
		return hm.authorizationError(w, r)
	}

	isOutOftime := hm.checkClockSkew(r.Header.Get(DateHeaderSpec))
	if isOutOftime == false {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": r.RemoteAddr,
		}).Info("Date is out of allowed range.")

		handler := ErrorHandler{hm.TykMiddleware}
		handler.HandleError(w, r, "Date is out of allowed range.", 400)
		return errors.New("Date is out of allowed range."), 400
	}

	log.Debug("Got date")

	// Extract the keyId:
	splitTypes := strings.Split(authHeaderValue, " ")
	if len(splitTypes) != 2 {
		return hm.authorizationError(w, r)
	}

	log.Debug("Found two fields")

	if strings.ToLower(splitTypes[0]) != "signature" {
		return hm.authorizationError(w, r)
	}

	log.Debug("Found signature value field")

	splitValues := strings.Split(splitTypes[1], ",")
	if len(splitValues) != 3 {
		log.Debug("Comma length is wrong - got: ", splitValues)
		return hm.authorizationError(w, r)
	}

	log.Debug("Found 2 commas - getting elements of signature")

	// extract the keyId, algorithm and signature
	keyId := ""
	algorithm := ""
	signature := ""
	for _, v := range splitValues {
		splitKeyValuePair := strings.Split(v, "=")
		if len(splitKeyValuePair) != 2 {
			log.Debug("Equals length is wrong - got: ", splitKeyValuePair)
			return hm.authorizationError(w, r)
		}
		if strings.ToLower(splitKeyValuePair[0]) == "keyid" {
			keyId = strings.Trim(splitKeyValuePair[1], "\"")
		}
		if strings.ToLower(splitKeyValuePair[0]) == "algorithm" {
			algorithm = strings.Trim(splitKeyValuePair[1], "\"")
		}
		if strings.ToLower(splitKeyValuePair[0]) == "signature" {
			signature = strings.Trim(splitKeyValuePair[1], "\"")
		}
	}

	log.Debug("Extracted values... checking validity")

	// None may be empty
	if keyId == "" || algorithm == "" || signature == "" {
		return hm.authorizationError(w, r)
	}

	log.Debug("Key is valid: ", keyId)
	log.Debug("algo is valid: ", algorithm)
	log.Debug("signature isn't empty: ", signature)

	// Check if API key valid
	thisSessionState, keyExists :=hm.TykMiddleware.CheckSessionAndIdentityForValidKey(keyId)
	if !keyExists {
		return hm.authorizationError(w, r)
	}

	log.Debug("Found key in session store")

	// Set session state on context, we will need it later
	context.Set(r, SessionData, thisSessionState)
	context.Set(r, AuthHeaderValue, keyId)

	if thisSessionState.HmacSecret == "" || thisSessionState.HMACEnabled == false {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": r.RemoteAddr,
		}).Info("API Requires HMAC signature, session missing HMACSecret or HMAC not enabled for key")

		return errors.New("This key is invalid"), 400
	}

	log.Debug("Sessionstate is HMAC enabled")

	ourSignature := hm.generateSignatureFromRequest(r, thisSessionState.HmacSecret)
	log.Debug("Our Signature: ", ourSignature)

	compareTo, err := url.QueryUnescape(signature)

	if err != nil {
		return hm.authorizationError(w, r)
	}

	log.Debug("Request Signature: ", compareTo)
	if ourSignature != compareTo {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": r.RemoteAddr,
		}).Info("Request signature is invalid")

		// Fire Authfailed Event
		AuthFailed(hm.TykMiddleware, r, keyId)

		return errors.New("Request signature is invalid"), 400
	}

	log.Debug("Signature matches")

	// Everything seems in order let the request through
	return nil, 200
}

// New creates a new HttpHandler for the alice middleware package, key implementation is here https://web-payments.org/specs/ED/http-signatures/2014-02-01/
//func (hm HMACMiddleware) New() func(http.Handler) http.Handler {
//	aliceHandler := func(h http.Handler) http.Handler {
//		thisHandler := func(w http.ResponseWriter, r *http.Request) {
//
//			log.Debug("HMAC middleware activated")
//
//			authHeaderValue := r.Header.Get("Authorization")
//			if authHeaderValue == "" {
//				hm.authorizationError(w, r)
//				return
//			}
//
//			log.Debug("Got auth header")
//
//			if r.Header.Get(DateHeaderSpec) == "" {
//				log.Debug("Date missing")
//				hm.authorizationError(w, r)
//				return
//			}
//
//			isOutOftime := hm.checkClockSkew(r.Header.Get(DateHeaderSpec))
//			if isOutOftime == false {
//				log.WithFields(logrus.Fields{
//					"path":   r.URL.Path,
//					"origin": r.RemoteAddr,
//				}).Info("Date is out of allowed range.")
//
//				handler := ErrorHandler{hm.TykMiddleware}
//				handler.HandleError(w, r, "Date is out of allowed range.", 400)
//				return
//			}
//
//			log.Debug("Got date")
//
//			// Extract the keyId:
//			splitTypes := strings.Split(authHeaderValue, " ")
//			if len(splitTypes) != 2 {
//				hm.authorizationError(w, r)
//				return
//			}
//
//			log.Debug("Found two fields")
//
//			if strings.ToLower(splitTypes[0]) != "signature" {
//				hm.authorizationError(w, r)
//				return
//			}
//
//			log.Debug("Found signature value field")
//
//			splitValues := strings.Split(splitTypes[1], ",")
//			if len(splitValues) != 3 {
//				log.Debug("Comma length is wrong - got: ", splitValues)
//				hm.authorizationError(w, r)
//				return
//			}
//
//			log.Debug("Found 2 commas - getting elements of signature")
//
//			// extract the keyId, algorithm and signature
//			keyId := ""
//			algorithm := ""
//			signature := ""
//			for _, v := range splitValues {
//				splitKeyValuePair := strings.Split(v, "=")
//				if len(splitKeyValuePair) != 2 {
//					hm.authorizationError(w, r)
//					log.Debug("Equals length is wrong - got: ", splitKeyValuePair)
//					return
//				}
//				if strings.ToLower(splitKeyValuePair[0]) == "keyid" {
//					keyId = strings.Trim(splitKeyValuePair[1], "\"")
//				}
//				if strings.ToLower(splitKeyValuePair[0]) == "algorithm" {
//					algorithm = strings.Trim(splitKeyValuePair[1], "\"")
//				}
//				if strings.ToLower(splitKeyValuePair[0]) == "signature" {
//					signature = strings.Trim(splitKeyValuePair[1], "\"")
//				}
//			}
//
//			log.Debug("Extracted values... checking validity")
//
//			// None may be empty
//			if keyId == "" || algorithm == "" || signature == "" {
//				hm.authorizationError(w, r)
//				return
//			}
//
//			log.Debug("Key is valid: ", keyId)
//			log.Debug("algo is valid: ", algorithm)
//			log.Debug("signature isn't empty: ", signature)
//
//			// Check if API key valid
//			keyExists, thisSessionState := authManager.IsKeyAuthorised(keyId)
//			if !keyExists {
//				hm.authorizationError(w, r)
//				return
//			}
//
//			log.Debug("Found key in session store")
//
//			// Set session state on context, we will need it later
//			context.Set(r, SessionData, thisSessionState)
//			context.Set(r, AuthHeaderValue, keyId)
//
//			if thisSessionState.HmacSecret == "" || thisSessionState.HMACEnabled == false {
//				log.WithFields(logrus.Fields{
//					"path":   r.URL.Path,
//					"origin": r.RemoteAddr,
//				}).Info("API Requires HMAC signature, session missing HMACSecret or HMAC not enabled for key")
//
//				handler := ErrorHandler{hm.TykMiddleware}
//				handler.HandleError(w, r, "This key is invalid", 400)
//				return
//			}
//
//			log.Debug("Sessionstate is HMAC enabled")
//
//			ourSignature := hm.generateSignatureFromRequest(r, thisSessionState.HmacSecret)
//			log.Debug("Our Signature: ", ourSignature)
//
//			compareTo, err := url.QueryUnescape(signature)
//
//			if err != nil {
//				hm.authorizationError(w, r)
//				return
//			}
//
//			log.Debug("Request Signature: ", compareTo)
//			if ourSignature != compareTo {
//				log.WithFields(logrus.Fields{
//					"path":   r.URL.Path,
//					"origin": r.RemoteAddr,
//				}).Info("Request signature is invalid")
//
//				handler := ErrorHandler{hm.TykMiddleware}
//				handler.HandleError(w, r, "Request signature is invalid", 400)
//				return
//			}
//
//			log.Debug("Signature matches")
//
//			// Everything seems in order let the request through
//			h.ServeHTTP(w, r)
//		}
//		return http.HandlerFunc(thisHandler)
//	}
//	return aliceHandler
//}

func (hm HMACMiddleware) parseFormParams(values url.Values) string {
	kvValues := map[string]string{}
	keys := []string{}

	log.Debug("Parsing header values")

	for k, v := range values {
		log.Debug("Form parser - processing key: ", k)
		log.Debug("Form parser - processing value: ", v)
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

	date_header := url.QueryEscape(r.Header.Get(DateHeaderSpec))

	// Not using form params for now, just date string
	//params := url.QueryEscape(hm.parseFormParams(r.Form))

	// Prep the signature string
	signatureString := strings.ToLower(DateHeaderSpec) + ":" + date_header

	log.Debug("Signature string before encoding: ", signatureString)

	// Encode it
	key := []byte(secret)
	h := hmac.New(sha1.New, key)
	h.Write([]byte(signatureString))

	encodedString := base64.StdEncoding.EncodeToString(h.Sum(nil))
	log.Debug("Encoded signature string: ", encodedString)
	log.Debug("URL Encoded: ", url.QueryEscape(encodedString))

	// Return as base64
	return encodedString
}

func (hm HMACMiddleware) checkClockSkew(dateHeaderValue string) bool {
	// Reference layout for parsing time: "Mon Jan 2 15:04:05 MST 2006"

	refDate := "Mon, 02 Jan 2006 15:04:05 MST"

	tim, err := time.Parse(refDate, dateHeaderValue)

	if err != nil {
		log.Error("Date parsing failed")
		return false
	}

	inSec := tim.UnixNano()
	now := time.Now().UnixNano()

	diff := now - inSec

	in_ms := diff / 1000000
	if math.Abs(float64(in_ms)) > HMACClockSkewLimitInMs {
		log.Debug("Difference is: ", math.Abs(float64(in_ms)))
		return false
	}

	return true
}

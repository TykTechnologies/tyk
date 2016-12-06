package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"github.com/TykTechnologies/logrus"
	"github.com/TykTechnologies/tykcommon"
	"github.com/gorilla/context"
	"math"
	"net/http"
	"regexp"
	"net/url"
	"strings"
	"time"
)

const DateHeaderSpec string = "Date"
const AltHeaderSpec string = "x-aux-date"
const HMACClockSkewLimitInMs float64 = 1000

// HMACMiddleware will check if the request has a signature, and if the request is allowed through
type HMACMiddleware struct {
	*TykMiddleware
	lowercasePattern *regexp.Regexp
}

// New lets you do any initializations for the object can be done here
func (hm *HMACMiddleware) New() {
	hm.lowercasePattern, _ = regexp.Compile("%[a-f0-9][a-f0-9]")
}

func (a *HMACMiddleware) IsEnabledForSpec() bool {
	return true
}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (hm *HMACMiddleware) GetConfig() (interface{}, error) {
	return nil, nil
}

func (hm *HMACMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	authHeaderValue := r.Header.Get("Authorization")
	if authHeaderValue == "" {
		return hm.authorizationError(w, r)
	}

	// Clean it
	authHeaderValue = stripSignature(authHeaderValue)

	log.Debug(authHeaderValue)

	// Separate out the field values
	fieldValues, fErr := getFieldValues(authHeaderValue)
	if fErr != nil {
		log.WithFields(logrus.Fields{
			"prefix": "hmac",
			"error":  fErr,
			"header": authHeaderValue,
		}).Error("Field extraction failed")
		return hm.authorizationError(w, r)
	}

	// Generate a signature string
	signatureString, sErr := generateHMACSignatureStringFromRequest(r, fieldValues)
	if sErr != nil {
		log.WithFields(logrus.Fields{
			"prefix":           "hmac",
			"error":            fErr,
			"signature_string": signatureString,
		}).Error("Signature string generation failed")
		return hm.authorizationError(w, r)
	}

	// Get a session for the Key ID
	thisSecret, thisSessionState, keyError := hm.getSecretAndSessionForKeyID(fieldValues.KeyID)
	if keyError != nil {
		log.WithFields(logrus.Fields{
			"prefix": "hmac",
			"error":  keyError,
			"keyID":  fieldValues.KeyID,
		}).Error("No HMAC secret for this key")
		return hm.authorizationError(w, r)
	}

	// Create a signed string with the secret
	encodedSignature := generateEncodedSignature(signatureString, thisSecret)

	// Compare
	matchPass := false
	if encodedSignature == fieldValues.Signature {
		matchPass = true
	}

	// Check for lower case encoding (.Net issues, again)
	if !matchPass {
		isLower, lowerList := hm.hasLowerCaseEscaped(fieldValues.Signature)
		if isLower {
			log.Debug("--- Detected lower case encoding! ---")
			upperedSignature := hm.replaceWithUpperCase(fieldValues.Signature, lowerList)
			if encodedSignature == upperedSignature {
				matchPass = true
				encodedSignature = upperedSignature
			}
		}
	}

	if matchPass == false {
		log.WithFields(logrus.Fields{
			"prefix":   "hmac",
			"expected": encodedSignature,
			"got":      fieldValues.Signature,
		}).Error("Signature string does not match!")
		return hm.authorizationError(w, r)
	}

	// Check clock skew
	_, dateVal := getDateHeader(r)
	if !hm.checkClockSkew(dateVal) {
		log.WithFields(logrus.Fields{
			"prefix": "hmac",
		}).Error("Clock skew outside of acceptable bounds")
		return hm.authorizationError(w, r)
	}

	// Set session state on context, we will need it later
	if (hm.TykMiddleware.Spec.BaseIdentityProvidedBy == tykcommon.HMACKey) || (hm.TykMiddleware.Spec.BaseIdentityProvidedBy == tykcommon.UnsetAuth) {
		context.Set(r, SessionData, thisSessionState)
		context.Set(r, AuthHeaderValue, fieldValues.KeyID)
		hm.setContextVars(r, fieldValues.KeyID)
	}

	// Everything seems in order let the request through
	return nil, 200

}

func (hm *HMACMiddleware) hasLowerCaseEscaped(signature string) (bool, []string) {
	foundList := hm.lowercasePattern.FindAllString(signature, -1)
	if len(foundList) > 0 {
		return true, foundList
	}

	return false, foundList
}

func (hm *HMACMiddleware) replaceWithUpperCase(originalSignature string, lowercaseList []string) string {
	newSignature := originalSignature
	for _, lStr := range(lowercaseList) {
		asUpper := strings.ToUpper(lStr)
		newSignature = strings.Replace(newSignature, lStr, asUpper, -1)
	}

	return newSignature
}

func (hm *HMACMiddleware) setContextVars(r *http.Request, token string) {
	// Flatten claims and add to context
	if hm.Spec.EnableContextVars {
		cnt, contextFound := context.GetOk(r, ContextData)
		var contextDataObject map[string]interface{}
		if contextFound {
			// Key data
			contextDataObject = cnt.(map[string]interface{})
			contextDataObject["token"] = token
			context.Set(r, ContextData, contextDataObject)
		}
	}
}

func (hm *HMACMiddleware) authorizationError(w http.ResponseWriter, r *http.Request) (error, int) {
	log.WithFields(logrus.Fields{
		"prefix": "hmac",
		"path":   r.URL.Path,
		"origin": r.RemoteAddr,
	}).Info("Authorization field missing or malformed")

	return errors.New("Authorization field missing, malformed or invalid"), 400
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

type HMACFieldValues struct {
	KeyID     string
	Algorthm  string
	Headers   []string
	Signature string
}

func (hm *HMACMiddleware) getSecretAndSessionForKeyID(keyId string) (string, SessionState, error) {
	thisSessionState, keyExists := hm.TykMiddleware.CheckSessionAndIdentityForValidKey(keyId)
	if !keyExists {
		return "", thisSessionState, errors.New("Key ID does not exist")
	}

	if thisSessionState.HmacSecret == "" || thisSessionState.HMACEnabled == false {
		log.WithFields(logrus.Fields{
			"prefix": "hmac",
		}).Info("API Requires HMAC signature, session missing HMACSecret or HMAC not enabled for key")

		return "", thisSessionState, errors.New("This key ID is invalid")
	}

	return thisSessionState.HmacSecret, thisSessionState, nil
}

func getDateHeader(r *http.Request) (string, string) {

	auxHeaderVal := r.Header.Get(AltHeaderSpec)
	dateHeaderVal := r.Header.Get(DateHeaderSpec)

	// Prefer aux if present
	if auxHeaderVal != "" {
		authHeaderValue := r.Header.Get("Authorization")
		log.WithFields(logrus.Fields{
			"prefix":      "hmac",
			"auth_header": authHeaderValue,
		}).Warning("Using auxiliary header for this request")
		return strings.ToLower(AltHeaderSpec), auxHeaderVal
	}

	if dateHeaderVal != "" {
		log.WithFields(logrus.Fields{
			"prefix": "hmac",
		}).Debug("Got date header")
		return strings.ToLower(DateHeaderSpec), dateHeaderVal
	}

	return "", ""
}

var validKeyHeaders map[string]bool = map[string]bool{
	"keyid":     true,
	"algorithm": true,
	"headers":   true,
	"signature": true,
}

func isHeaderFieldKeyValid(key string) bool {
	_, found := validKeyHeaders[key]
	return found
}

func getFieldValues(authHeader string) (*HMACFieldValues, error) {
	AsElements := strings.Split(authHeader, ",")
	thisSet := HMACFieldValues{}

	for _, element := range AsElements {
		kv := strings.Split(element, "=")
		log.Debug("Checking: ", kv)
		if len(kv) < 2 {
			return nil, errors.New("Header field value malformed (less than two elements in field)")
		}
		if len(kv) > 2 {
			return nil, errors.New("Header field value malformed (more than two elements in field)")
		}

		key := strings.ToLower(kv[0])
		if !isHeaderFieldKeyValid(key) {
			log.WithFields(logrus.Fields{
				"prefix": "hmac",
				"field":  kv[0],
			}).Warning("Invalid header field found")
			return nil, errors.New("Header key is not valid, not in allowed parameter list")
		}

		value := kv[1]
		value = strings.Trim(value, "\"")

		switch key {
		case "keyid":
			thisSet.KeyID = value
		case "algorithm":
			thisSet.Algorthm = value
		case "headers":
			thisSet.Headers = strings.Split(value, " ")
		case "signature":
			thisSet.Signature = value
		}
	}

	// Date is the absolute minimum header set
	if len(thisSet.Headers) == 0 {
		thisSet.Headers = append(thisSet.Headers, "date")
	}

	return &thisSet, nil
}

// "Signature keyId="9876",algorithm="hmac-sha1",headers="x-test x-test-2",signature="queryEscape(base64(sig))"")

func generateHMACSignatureStringFromRequest(r *http.Request, fieldValues *HMACFieldValues) (string, error) {
	signatureString := ""
	for i, header := range fieldValues.Headers {
		loweredHeader := strings.TrimSpace(strings.ToLower(header))
		if loweredHeader == "(request-target)" {
			requestHeaderField := "(request-target): " + strings.ToLower(r.Method) + " " + r.URL.Path
			signatureString += requestHeaderField
		} else {
			// exception for dates and .Net oddness
			headerVal := r.Header.Get(loweredHeader)
			if loweredHeader == "date" {
				loweredHeader, headerVal = getDateHeader(r)
			}
			headerField := strings.TrimSpace(loweredHeader) + ": " + strings.TrimSpace(headerVal)
			signatureString += headerField
		}

		if i != (len(fieldValues.Headers) - 1) {
			signatureString += "\n"
		}
	}
	log.Debug("Generated sig string: ", signatureString)
	return signatureString, nil
}

func generateEncodedSignature(signatureString string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha1.New, key)
	h.Write([]byte(signatureString))

	encodedString := base64.StdEncoding.EncodeToString(h.Sum(nil))
	encodedString = url.QueryEscape(encodedString)
	return encodedString
}

func generateAuthHeaderValue(fieldValues *HMACFieldValues) string {
	authHeaderString := "Signature "
	authHeaderString += "keyId=" + fieldValues.KeyID + ","
	authHeaderString += "algorithm=" + fieldValues.Algorthm + ","
	if len(fieldValues.Headers) > 0 {
		headers := strings.Join(fieldValues.Headers, " ")
		authHeaderString += "headers=" + headers
	}
	authHeaderString += ", signature=" + fieldValues.Signature

	return authHeaderString
}

package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"
)

const dateHeaderSpec = "Date"
const altHeaderSpec = "x-aux-date"

// HMACMiddleware will check if the request has a signature, and if the request is allowed through
type HMACMiddleware struct {
	BaseMiddleware
	lowercasePattern *regexp.Regexp
}

func (hm *HMACMiddleware) Name() string {
	return "HMAC"
}

func (k *HMACMiddleware) EnabledForSpec() bool {
	return k.Spec.EnableSignatureChecking
}

func (hm *HMACMiddleware) Init() {
	hm.lowercasePattern = regexp.MustCompile(`%[a-f0-9][a-f0-9]`)
}

func (hm *HMACMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	token := r.Header.Get("Authorization")
	if token == "" {
		return hm.authorizationError(r)
	}

	// Clean it
	token = stripSignature(token)

	log.Debug(token)

	// Separate out the field values
	fieldValues, err := getFieldValues(token)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "hmac",
			"error":  err,
			"header": token,
		}).Error("Field extraction failed")
		return hm.authorizationError(r)
	}

	// Generate a signature string
	signatureString, err := generateHMACSignatureStringFromRequest(r, fieldValues)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix":           "hmac",
			"error":            err,
			"signature_string": signatureString,
		}).Error("Signature string generation failed")
		return hm.authorizationError(r)
	}

	// Get a session for the Key ID
	secret, session, err := hm.getSecretAndSessionForKeyID(fieldValues.KeyID)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "hmac",
			"error":  err,
			"keyID":  fieldValues.KeyID,
		}).Error("No HMAC secret for this key")
		return hm.authorizationError(r)
	}

	// Create a signed string with the secret
	encodedSignature := generateEncodedSignature(signatureString, secret)

	// Compare
	matchPass := encodedSignature == fieldValues.Signature

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

	if !matchPass {
		log.WithFields(logrus.Fields{
			"prefix":   "hmac",
			"expected": encodedSignature,
			"got":      fieldValues.Signature,
		}).Error("Signature string does not match!")
		return hm.authorizationError(r)
	}

	// Check clock skew
	_, dateVal := getDateHeader(r)
	if !hm.checkClockSkew(dateVal) {
		log.WithFields(logrus.Fields{
			"prefix": "hmac",
		}).Error("Clock skew outside of acceptable bounds")
		return hm.authorizationError(r)
	}

	// Set session state on context, we will need it later
	switch hm.Spec.BaseIdentityProvidedBy {
	case apidef.HMACKey, apidef.UnsetAuth:
		ctxSetSession(r, &session)
		ctxSetAuthToken(r, fieldValues.KeyID)
		hm.setContextVars(r, fieldValues.KeyID)
	}

	// Everything seems in order let the request through
	return nil, 200

}

func stripSignature(token string) string {
	token = strings.TrimPrefix(token, "Signature")
	token = strings.TrimPrefix(token, "signature")
	return strings.TrimSpace(token)
}

func (hm *HMACMiddleware) hasLowerCaseEscaped(signature string) (bool, []string) {
	foundList := hm.lowercasePattern.FindAllString(signature, -1)
	return len(foundList) > 0, foundList
}

func (hm *HMACMiddleware) replaceWithUpperCase(originalSignature string, lowercaseList []string) string {
	newSignature := originalSignature
	for _, lStr := range lowercaseList {
		asUpper := strings.ToUpper(lStr)
		newSignature = strings.Replace(newSignature, lStr, asUpper, -1)
	}

	return newSignature
}

func (hm *HMACMiddleware) setContextVars(r *http.Request, token string) {
	if !hm.Spec.EnableContextVars {
		return
	}
	// Flatten claims and add to context
	if cnt := ctxGetData(r); cnt != nil {
		// Key data
		cnt["token"] = token
		ctxSetData(r, cnt)
	}
}

func (hm *HMACMiddleware) authorizationError(r *http.Request) (error, int) {
	logEntry := getLogEntryForRequest(r, "", nil)
	logEntry.Info("Authorization field missing or malformed")

	AuthFailed(hm, r, r.Header.Get("Authorization"))

	return errors.New("Authorization field missing, malformed or invalid"), 400
}

func (hm HMACMiddleware) checkClockSkew(dateHeaderValue string) bool {
	// Reference layout for parsing time: "Mon Jan 2 15:04:05 MST 2006"
	refDate := "Mon, 02 Jan 2006 15:04:05 MST"
	// Fall back to a numeric timezone, since some environments don't provide a timezone name code
	refDateNumeric := "Mon, 02 Jan 2006 15:04:05 -07"

	tim, err := time.Parse(refDate, dateHeaderValue)
	if err != nil {
		tim, err = time.Parse(refDateNumeric, dateHeaderValue)
	}

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

	if hm.Spec.HmacAllowedClockSkew <= 0 {
		return true
	}

	if math.Abs(float64(in_ms)) > hm.Spec.HmacAllowedClockSkew {
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

func (hm *HMACMiddleware) getSecretAndSessionForKeyID(keyId string) (string, user.SessionState, error) {
	session, keyExists := hm.CheckSessionAndIdentityForValidKey(keyId)
	if !keyExists {
		return "", session, errors.New("Key ID does not exist")
	}

	if session.HmacSecret == "" || !session.HMACEnabled {
		log.WithFields(logrus.Fields{
			"prefix": "hmac",
		}).Info("API Requires HMAC signature, session missing HMACSecret or HMAC not enabled for key")

		return "", session, errors.New("This key ID is invalid")
	}

	return session.HmacSecret, session, nil
}

func getDateHeader(r *http.Request) (string, string) {

	auxHeaderVal := r.Header.Get(altHeaderSpec)
	// Prefer aux if present
	if auxHeaderVal != "" {
		token := r.Header.Get("Authorization")
		log.WithFields(logrus.Fields{
			"prefix":      "hmac",
			"auth_header": token,
		}).Warning("Using auxiliary header for this request")
		return strings.ToLower(altHeaderSpec), auxHeaderVal
	}

	dateHeaderVal := r.Header.Get(dateHeaderSpec)
	if dateHeaderVal != "" {
		log.WithFields(logrus.Fields{
			"prefix": "hmac",
		}).Debug("Got date header")
		return strings.ToLower(dateHeaderSpec), dateHeaderVal
	}

	return "", ""
}

func getFieldValues(authHeader string) (*HMACFieldValues, error) {
	set := HMACFieldValues{}

	for _, element := range strings.Split(authHeader, ",") {
		kv := strings.Split(element, "=")
		if len(kv) != 2 {
			return nil, errors.New("Header field value malformed (need two elements in field)")
		}

		key := strings.ToLower(kv[0])
		value := strings.Trim(kv[1], `"`)

		switch key {
		case "keyid":
			set.KeyID = value
		case "algorithm":
			set.Algorthm = value
		case "headers":
			set.Headers = strings.Split(value, " ")
		case "signature":
			set.Signature = value
		default:
			log.WithFields(logrus.Fields{
				"prefix": "hmac",
				"field":  kv[0],
			}).Warning("Invalid header field found")
			return nil, errors.New("Header key is not valid, not in allowed parameter list")
		}
	}

	// Date is the absolute minimum header set
	if len(set.Headers) == 0 {
		set.Headers = append(set.Headers, "date")
	}

	return &set, nil
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

		if i != len(fieldValues.Headers)-1 {
			signatureString += "\n"
		}
	}
	log.Debug("Generated sig string: ", signatureString)
	return signatureString, nil
}

func generateEncodedSignature(signatureString, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha1.New, key)
	h.Write([]byte(signatureString))

	encodedString := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return url.QueryEscape(encodedString)
}

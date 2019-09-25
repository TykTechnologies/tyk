package gateway

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"hash"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"text/scanner"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/headers"
	"github.com/TykTechnologies/tyk/regexp"
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
	logger := hm.Logger().WithField("key", obfuscateKey(token))

	// Clean it
	token = stripSignature(token)

	// Separate out the field values
	fieldValues, err := getFieldValues(token)
	if err != nil {
		logger.WithError(err).Error("Field extraction failed")
		return hm.authorizationError(r)
	}

	// Generate a signature string
	signatureString, err := generateHMACSignatureStringFromRequest(r, fieldValues.Headers)
	if err != nil {
		logger.WithError(err).WithField("signature_string", signatureString).Error("Signature string generation failed")
		return hm.authorizationError(r)
	}

	// Get a session for the Key ID
	secret, session, err := hm.getSecretAndSessionForKeyID(r, fieldValues.KeyID)
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{
			"keyID": fieldValues.KeyID,
		}).Error("No HMAC secret for this key")
		return hm.authorizationError(r)
	}

	if len(hm.Spec.HmacAllowedAlgorithms) > 0 {
		algorithmAllowed := false
		for _, alg := range hm.Spec.HmacAllowedAlgorithms {
			if alg == fieldValues.Algorthm {
				algorithmAllowed = true
				break
			}
		}
		if !algorithmAllowed {
			logger.WithError(err).WithField("algorithm", fieldValues.Algorthm).Error("Algorithm not supported")
			return hm.authorizationError(r)
		}
	}

	// Create a signed string with the secret
	encodedSignature := generateEncodedSignature(signatureString, secret, fieldValues.Algorthm)

	// Compare
	matchPass := encodedSignature == fieldValues.Signature

	// Check for lower case encoding (.Net issues, again)
	if !matchPass {
		isLower, lowerList := hm.hasLowerCaseEscaped(fieldValues.Signature)
		if isLower {
			logger.Debug("--- Detected lower case encoding! ---")
			upperedSignature := hm.replaceWithUpperCase(fieldValues.Signature, lowerList)
			if encodedSignature == upperedSignature {
				matchPass = true
				encodedSignature = upperedSignature
			}
		}
	}

	if !matchPass {
		logger.WithFields(logrus.Fields{
			"expected": encodedSignature,
			"got":      fieldValues.Signature,
		}).Error("Signature string does not match!")
		return hm.authorizationError(r)
	}

	// Check clock skew
	_, dateVal := getDateHeader(r)
	if !hm.checkClockSkew(dateVal) {
		logger.Error("Clock skew outside of acceptable bounds")
		return hm.authorizationError(r)
	}

	// Set session state on context, we will need it later
	switch hm.Spec.BaseIdentityProvidedBy {
	case apidef.HMACKey, apidef.UnsetAuth:
		ctxSetSession(r, &session, fieldValues.KeyID, false)
		hm.setContextVars(r, fieldValues.KeyID)
	}

	// Everything seems in order let the request through
	return nil, http.StatusOK
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
	hm.Logger().Info("Authorization field missing or malformed")

	AuthFailed(hm, r, r.Header.Get(headers.Authorization))

	return errors.New("Authorization field missing, malformed or invalid"), http.StatusBadRequest
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
		hm.Logger().WithError(err).WithField("date_string", tim).Error("Date parsing failed")
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
		hm.Logger().Debug("Difference is: ", math.Abs(float64(in_ms)))
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

func (hm *HMACMiddleware) getSecretAndSessionForKeyID(r *http.Request, keyId string) (string, user.SessionState, error) {
	session, keyExists := hm.CheckSessionAndIdentityForValidKey(keyId, r)
	if !keyExists {
		return "", session, errors.New("Key ID does not exist")
	}

	if session.HmacSecret == "" || !session.HMACEnabled {
		hm.Logger().Info("API Requires HMAC signature, session missing HMACSecret or HMAC not enabled for key")

		return "", session, errors.New("This key ID is invalid")
	}

	return session.HmacSecret, session, nil
}

func getDateHeader(r *http.Request) (string, string) {
	auxHeaderVal := r.Header.Get(altHeaderSpec)
	// Prefer aux if present
	if auxHeaderVal != "" {
		token := r.Header.Get(headers.Authorization)
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

// parses v which is a string of key1=value1,,key2=value2 ... format and returns
// a map of key:value pairs.
func loadKeyValues(v string) map[string]string {
	s := &scanner.Scanner{}
	s.Init(strings.NewReader(v))
	m := make(map[string]string)
	// the state of the scanner.
	// 0 - key
	// 1 - value
	var mode int
	var key string
	for {
		tok := s.Scan()
		if tok == scanner.EOF {
			break
		}
		text := s.TokenText()
		switch text {
		case "=":
			mode = 1
			continue
		case ",":
			mode = 0
			continue
		default:
			switch mode {
			case 0:
				key = text
				mode = 1
			case 1:
				m[key] = text
				mode = 0
			}
		}
	}
	return m
}

func getFieldValues(authHeader string) (*HMACFieldValues, error) {
	set := HMACFieldValues{}
	m := loadKeyValues(authHeader)
	for key, value := range m {
		if len(value) > 0 && value[0] == '"' {
			v, err := strconv.Unquote(m[key])
			if err != nil {
				return nil, err
			}
			value = v
		}
		switch strings.ToLower(key) {
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
				"field":  key,
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

func generateHMACSignatureStringFromRequest(r *http.Request, headers []string) (string, error) {
	signatureString := ""
	for i, header := range headers {
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

		if i != len(headers)-1 {
			signatureString += "\n"
		}
	}
	log.Debug("Generated sig string: ", signatureString)
	return signatureString, nil
}

func generateEncodedSignature(signatureString, secret string, algorithm string) string {
	key := []byte(secret)

	var hashFunction func() hash.Hash

	switch algorithm {
	case "hmac-sha256":
		hashFunction = sha256.New
	case "hmac-sha384":
		hashFunction = sha512.New384
	case "hmac-sha512":
		hashFunction = sha512.New
	default:
		hashFunction = sha1.New
	}

	h := hmac.New(hashFunction, key)
	h.Write([]byte(signatureString))
	encodedString := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return url.QueryEscape(encodedString)
}

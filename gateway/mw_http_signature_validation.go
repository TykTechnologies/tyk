package gateway

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
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
	"github.com/TykTechnologies/tyk/regexp"
	"github.com/TykTechnologies/tyk/user"
)

const dateHeaderSpec = "Date"
const altHeaderSpec = "x-aux-date"

// HTTPSignatureValidationMiddleware will check if the request has a signature, and if the request is allowed through
type HTTPSignatureValidationMiddleware struct {
	BaseMiddleware
	lowercasePattern *regexp.Regexp
}

func (hm *HTTPSignatureValidationMiddleware) Name() string {
	return "HTTPSignatureValidationMiddleware"
}

func (k *HTTPSignatureValidationMiddleware) EnabledForSpec() bool {
	return k.Spec.EnableSignatureChecking
}

func (hm *HTTPSignatureValidationMiddleware) Init() {
	hm.lowercasePattern = regexp.MustCompile(`%[a-f0-9][a-f0-9]`)
}

// getAuthType overrides BaseMiddleware.getAuthType.
func (hm *HTTPSignatureValidationMiddleware) getAuthType() string {
	return apidef.HMACType
}

func (hm *HTTPSignatureValidationMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if ctxGetRequestStatus(r) == StatusOkAndIgnore {
		return nil, http.StatusOK
	}

	token, _ := hm.getAuthToken(hm.getAuthType(), r)
	if token == "" {
		return hm.authorizationError(r)
	}
	logger := hm.Logger().WithField("key", hm.Gw.obfuscateKey(token))

	// Clean it
	token = stripSignature(token)

	// Separate out the field values
	fieldValues, err := getFieldValues(token)
	if err != nil {
		logger.WithError(err).Error("Field extraction failed")
		return hm.authorizationError(r)
	}

	// Generate a signature string
	signatureString, err := generateHMACSignatureStringFromRequest(r, fieldValues.Headers, r.URL.Path)

	if err != nil {
		logger.WithError(err).WithField("signature_string", signatureString).Error("Signature string generation failed")
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

	var secret string
	var rsaKey *rsa.PublicKey
	var session user.SessionState

	if strings.HasPrefix(fieldValues.Algorthm, "rsa") {
		var certificateId string

		certificateId, session, err = hm.getRSACertificateIdAndSessionForKeyID(r, fieldValues.KeyID)
		if err != nil {
			logger.WithError(err).WithFields(logrus.Fields{
				"keyID": fieldValues.KeyID,
			}).Error("Failed to fetch session/public key")
			return hm.authorizationError(r)
		}

		publicKey := hm.Gw.CertificateManager.ListRawPublicKey(certificateId)
		if publicKey == nil {
			log.Error("Certificate not found")
			return errors.New("Certificate not found"), http.StatusInternalServerError
		}
		var ok bool
		rsaKey, ok = publicKey.(*rsa.PublicKey)
		if !ok {
			log.Error("Certificate doesn't contain RSA Public key")
			return errors.New("Certificate doesn't contain RSA Public key"), http.StatusInternalServerError
		}
	} else {
		// Get a session for the Key ID
		secret, session, err = hm.getSecretAndSessionForKeyID(r, fieldValues.KeyID)
		if err != nil {
			logger.WithError(err).WithFields(logrus.Fields{
				"keyID": fieldValues.KeyID,
			}).Error("No HMAC secret for this key")
			return hm.authorizationError(r)
		}
	}
	var matchPass bool

	if strings.HasPrefix(fieldValues.Algorthm, "rsa") {
		matchPass, err = validateRSAEncodedSignature(signatureString, rsaKey, fieldValues.Algorthm, fieldValues.Signature)
		if err != nil {
			logger.WithError(err).Error("Signature validation failed.")
		}

		if !matchPass {
			isLower, lowerList := hm.hasLowerCaseEscaped(fieldValues.Signature)
			if isLower {
				logger.Debug("--- Detected lower case encoding! ---")
				upperedSignature := hm.replaceWithUpperCase(fieldValues.Signature, lowerList)
				matchPass, err = validateRSAEncodedSignature(signatureString, rsaKey, fieldValues.Algorthm, upperedSignature)
				if err != nil {
					logger.WithError(err).Error("Signature validation failed.")
				}
			}
		}

		if !matchPass {
			logger.WithFields(logrus.Fields{
				"got": fieldValues.Signature,
			}).Error("Signature string does not match!")
			return hm.authorizationError(r)
		}
	} else {
		// Create a signed string with the secret
		encodedSignature, err := generateHMACEncodedSignature(signatureString, secret, fieldValues.Algorthm)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"error": err,
			}).Error("Failed to validate signature")
			return hm.authorizationError(r)
		}

		// Compare
		matchPass = encodedSignature == fieldValues.Signature

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
		session.KeyID = fieldValues.KeyID
		ctxSetSession(r, &session, false, hm.Gw.GetConfig().HashKeys)
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

func (hm *HTTPSignatureValidationMiddleware) hasLowerCaseEscaped(signature string) (bool, []string) {
	foundList := hm.lowercasePattern.FindAllString(signature, -1)
	return len(foundList) > 0, foundList
}

func (hm *HTTPSignatureValidationMiddleware) replaceWithUpperCase(originalSignature string, lowercaseList []string) string {
	newSignature := originalSignature
	for _, lStr := range lowercaseList {
		asUpper := strings.ToUpper(lStr)
		newSignature = strings.Replace(newSignature, lStr, asUpper, -1)
	}

	return newSignature
}

func (hm *HTTPSignatureValidationMiddleware) setContextVars(r *http.Request, token string) {
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

func (hm *HTTPSignatureValidationMiddleware) authorizationError(r *http.Request) (error, int) {
	hm.Logger().Info("Authorization field missing or malformed")
	token, _ := hm.getAuthToken(hm.getAuthType(), r)
	AuthFailed(hm, r, token)

	return errors.New("Authorization field missing, malformed or invalid"), http.StatusBadRequest
}

func (hm HTTPSignatureValidationMiddleware) checkClockSkew(dateHeaderValue string) bool {
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

func (hm *HTTPSignatureValidationMiddleware) getSecretAndSessionForKeyID(r *http.Request, keyId string) (string, user.SessionState, error) {
	session, keyExists := hm.CheckSessionAndIdentityForValidKey(keyId, r)
	keyId = session.KeyID
	if !keyExists {
		return "", session.Clone(), errors.New("Key ID does not exist")
	}

	if session.HmacSecret == "" || !session.HMACEnabled && !session.EnableHTTPSignatureValidation {
		hm.Logger().Info("API Requires HMAC signature, session missing HMACSecret or HMAC not enabled for key")

		return "", session.Clone(), errors.New("This key ID is invalid")
	}

	return session.HmacSecret, session.Clone(), nil
}

func (hm *HTTPSignatureValidationMiddleware) getRSACertificateIdAndSessionForKeyID(r *http.Request, keyId string) (string, user.SessionState, error) {
	session, keyExists := hm.CheckSessionAndIdentityForValidKey(keyId, r)
	keyId = session.KeyID
	if !keyExists {
		return "", session.Clone(), errors.New("Key ID does not exist")
	}

	if session.RSACertificateId == "" || !session.EnableHTTPSignatureValidation {
		hm.Logger().Info("API Requires RSA signature, session missing RSA Certificate Id or RSA not enabled for key")
		return "", session.Clone(), errors.New("This key ID is invalid")
	}

	return session.RSACertificateId, session.Clone(), nil
}

func getDateHeader(r *http.Request) (string, string) {
	auxHeaderVal := r.Header.Get(altHeaderSpec)
	// Prefer aux if present
	if auxHeaderVal != "" {
		log.WithFields(logrus.Fields{
			"prefix": "hmac",
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
func generateHMACSignatureStringFromRequest(r *http.Request, headers []string, path string) (string, error) {
	signatureString := ""
	for i, header := range headers {
		loweredHeader := strings.TrimSpace(strings.ToLower(header))
		if loweredHeader == "(request-target)" {
			requestHeaderField := "(request-target): " + strings.ToLower(r.Method) + " " + path
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

func generateHMACEncodedSignature(signatureString, secret string, algorithm string) (string, error) {
	if secret == "" {
		return "", errors.New("Hmac secret is empty")
	}

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
	return url.QueryEscape(encodedString), nil
}

func validateRSAEncodedSignature(signatureString string, publicKey *rsa.PublicKey, algorithm string, signature string) (bool, error) {
	var hashFunction hash.Hash
	var hashType crypto.Hash

	switch algorithm {
	case "rsa-sha256":
		hashFunction = sha256.New()
		hashType = crypto.SHA256
	default:
		hashFunction = sha256.New()
		hashType = crypto.SHA256
	}
	hashFunction.Write([]byte(signatureString))
	hashed := hashFunction.Sum(nil)

	decodedSignature, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		log.Error("Error while base64 decoding signature:", err)
		return false, err
	}
	err = rsa.VerifyPKCS1v15(publicKey, hashType, hashed, decodedSignature)
	if err != nil {
		log.Error("Signature match failed:", err)
		return false, err
	}

	return true, nil
}

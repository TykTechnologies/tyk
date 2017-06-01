package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/justinas/alice"
)

const hmacAuthDef = `{
	"api_id": "1",
	"org_id": "default",
	"enable_signature_checking": true,
	"hmac_allowed_clock_skew": 1000,
	"auth": {
		"auth_header_name": "authorization"
	},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"Default": {
				"name": "Default"
			}
		}
	},
	"proxy": {
		"listen_path": "/v1",
		"target_url": "` + testHttpAny + `"
	}
}`

func createHMACAuthSession() *SessionState {
	session := new(SessionState)
	session.Rate = 8.0
	session.Allowance = session.Rate
	session.LastCheck = time.Now().Unix()
	session.Per = 1.0
	session.QuotaRenewalRate = 300 // 5 minutes
	session.QuotaRenews = time.Now().Unix() + 20
	session.QuotaRemaining = 1
	session.QuotaMax = -1
	session.HMACEnabled = true
	session.HmacSecret = "9879879878787878"
	return session
}

func getHMACAuthChain(spec *APISpec) http.Handler {
	remote, _ := url.Parse(testHttpAny)
	proxy := TykNewSingleHostReverseProxy(remote, spec)
	proxyHandler := ProxyHandler(proxy, spec)
	tykMiddleware := &TykMiddleware{spec, proxy}
	chain := alice.New(
		CreateMiddleware(&IPWhiteListMiddleware{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&HMACMiddleware{TykMiddleware: tykMiddleware}, tykMiddleware),
		CreateMiddleware(&VersionCheck{TykMiddleware: tykMiddleware}, tykMiddleware),
		CreateMiddleware(&KeyExpired{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&AccessRightsCheck{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&RateLimitAndQuotaCheck{tykMiddleware}, tykMiddleware)).Then(proxyHandler)

	return chain
}

func TestHMACAuthSessionPass(t *testing.T) {
	spec := createSpecTest(t, hmacAuthDef)
	session := createHMACAuthSession()

	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("9876", session, 60)

	recorder := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/", nil)

	refDate := "Mon, 02 Jan 2006 15:04:05 MST"

	// Signature needs to be: Authorization: Signature keyId="hmac-key-1",algorithm="hmac-sha1",signature="Base64(HMAC-SHA1(signing string))"

	// Prep the signature string
	tim := time.Now().Format(refDate)
	req.Header.Add("Date", tim)
	signatureString := strings.ToLower("Date") + ": " + tim

	// Encode it
	key := []byte(session.HmacSecret)
	h := hmac.New(sha1.New, key)
	h.Write([]byte(signatureString))

	sigString := base64.StdEncoding.EncodeToString(h.Sum(nil))
	encodedString := url.QueryEscape(sigString)

	req.Header.Add("Authorization", fmt.Sprintf("Signature keyId=\"9876\",algorithm=\"hmac-sha1\",signature=\"%s\"", encodedString))

	if err != nil {
		t.Fatal(err)
	}

	chain := getHMACAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
	}
}

func TestHMACAuthSessionAuxDateHeader(t *testing.T) {
	spec := createSpecTest(t, hmacAuthDef)
	session := createHMACAuthSession()

	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("9876", session, 60)

	recorder := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/", nil)

	refDate := "Mon, 02 Jan 2006 15:04:05 MST"

	// Signature needs to be: Authorization: Signature keyId="hmac-key-1",algorithm="hmac-sha1",signature="Base64(HMAC-SHA1(signing string))"

	// Prep the signature string
	tim := time.Now().Format(refDate)
	req.Header.Add("x-aux-date", tim)
	signatureString := strings.ToLower("x-aux-date") + ": " + tim

	// Encode it
	key := []byte(session.HmacSecret)
	h := hmac.New(sha1.New, key)
	h.Write([]byte(signatureString))

	sigString := base64.StdEncoding.EncodeToString(h.Sum(nil))
	encodedString := url.QueryEscape(sigString)

	req.Header.Add("Authorization", fmt.Sprintf("Signature keyId=\"9876\",algorithm=\"hmac-sha1\",signature=\"%s\"", encodedString))

	if err != nil {
		t.Fatal(err)
	}

	chain := getHMACAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
	}
}

func TestHMACAuthSessionFailureDateExpired(t *testing.T) {
	spec := createSpecTest(t, hmacAuthDef)
	session := createHMACAuthSession()

	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("9876", session, 60)

	recorder := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/", nil)

	refDate := "Mon, 02 Jan 2006 15:04:05 MST"

	// Signature needs to be: Authorization: Signature keyId="hmac-key-1",algorithm="hmac-sha1",signature="Base64(HMAC-SHA1(signing string))"

	// Prep the signature string
	tim := time.Now().Format(refDate)
	req.Header.Add("Date", tim)
	signatureString := strings.ToLower("Date") + ":" + tim

	// Encode it
	key := []byte(session.HmacSecret)
	h := hmac.New(sha1.New, key)
	h.Write([]byte(signatureString))

	sigString := base64.StdEncoding.EncodeToString(h.Sum(nil))
	encodedString := url.QueryEscape(sigString)

	req.Header.Add("Authorization", fmt.Sprintf("Signature keyId=\"9876\",algorithm=\"hmac-sha1\",signature=\"%s\"", encodedString))

	if err != nil {
		t.Fatal(err)
	}

	chain := getHMACAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 400 {
		t.Error("Request should have failed with out of date error!: \n", recorder.Code)
	}
}

func TestHMACAuthSessionKeyMissing(t *testing.T) {
	spec := createSpecTest(t, hmacAuthDef)
	session := createHMACAuthSession()

	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("9876", session, 60)

	recorder := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/", nil)

	refDate := "Mon, 02 Jan 2006 15:04:05 MST"

	// Signature needs to be: Authorization: Signature keyId="hmac-key-1",algorithm="hmac-sha1",signature="Base64(HMAC-SHA1(signing string))"

	// Prep the signature string
	tim := time.Now().Format(refDate)
	req.Header.Add("Date", tim)
	signatureString := strings.ToLower("Date") + ":" + tim

	// Encode it
	key := []byte(session.HmacSecret)
	h := hmac.New(sha1.New, key)
	h.Write([]byte(signatureString))

	sigString := base64.StdEncoding.EncodeToString(h.Sum(nil))
	encodedString := url.QueryEscape(sigString)

	req.Header.Add("Authorization", fmt.Sprintf("Signature keyId=\"98765\",algorithm=\"hmac-sha1\",signature=\"%s\"", encodedString))

	if err != nil {
		t.Fatal(err)
	}

	chain := getHMACAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 400 {
		t.Error("Request should have failed with key not found error!: \n", recorder.Code)
	}
}

func TestHMACAuthSessionMalformedHeader(t *testing.T) {
	spec := createSpecTest(t, hmacAuthDef)
	session := createHMACAuthSession()

	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("9876", session, 60)

	recorder := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/", nil)

	refDate := "Mon, 02 Jan 2006 15:04:05 MST"

	// Signature needs to be: Authorization: Signature keyId="hmac-key-1",algorithm="hmac-sha1",signature="Base64(HMAC-SHA1(signing string))"

	// Prep the signature string
	tim := time.Now().Format(refDate)
	req.Header.Add("Date", tim)
	signatureString := strings.ToLower("Date") + ":" + tim

	// Encode it
	key := []byte(session.HmacSecret)
	h := hmac.New(sha1.New, key)
	h.Write([]byte(signatureString))

	sigString := base64.StdEncoding.EncodeToString(h.Sum(nil))
	encodedString := url.QueryEscape(sigString)

	req.Header.Add("Authorization", fmt.Sprintf("Signature keyID=\"98765\", algorithm=\"hmac-sha256\", signature=\"%s\"", encodedString))

	if err != nil {
		t.Fatal(err)
	}

	chain := getHMACAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 400 {
		t.Error("Request should have failed with key not found error!: \n", recorder.Code)
	}
}

func TestHMACAuthSessionPassWithHeaderField(t *testing.T) {
	spec := createSpecTest(t, hmacAuthDef)
	session := createHMACAuthSession()

	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("9876", session, 60)

	recorder := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/", nil)

	refDate := "Mon, 02 Jan 2006 15:04:05 MST"

	// Signature needs to be: Authorization: Signature keyId="hmac-key-1",algorithm="hmac-sha1",signature="Base64(HMAC-SHA1(signing string))"

	// Prep the signature string
	tim := time.Now().Format(refDate)
	req.Header.Add("Date", tim)
	req.Header.Add("X-Test-1", "hello")
	req.Header.Add("X-Test-2", "world")
	signatureString := strings.ToLower("(request-target): ") + "get /\n"
	signatureString += strings.ToLower("Date") + ": " + tim + "\n"
	signatureString += strings.ToLower("X-Test-1") + ": " + "hello" + "\n"
	signatureString += strings.ToLower("X-Test-2") + ": " + "world"

	// Encode it
	key := []byte(session.HmacSecret)
	h := hmac.New(sha1.New, key)
	h.Write([]byte(signatureString))

	sigString := base64.StdEncoding.EncodeToString(h.Sum(nil))
	encodedString := url.QueryEscape(sigString)

	req.Header.Add("Authorization", fmt.Sprintf("Signature keyId=\"9876\",algorithm=\"hmac-sha1\",headers=\"(request-target) date x-test-1 x-test-2\",signature=\"%s\"", encodedString))

	if err != nil {
		t.Fatal(err)
	}

	chain := getHMACAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
	}
}

func getUpperCaseEscaped(signature string) (bool, []string) {
	r := regexp.MustCompile(`%[A-F0-9][A-F0-9]`)
	foundList := r.FindAllString(signature, -1)
	return len(foundList) > 0, foundList
}

func replaceUpperCase(originalSignature string, lowercaseList []string) string {
	newSignature := originalSignature
	for _, lStr := range lowercaseList {
		asUpper := strings.ToLower(lStr)
		newSignature = strings.Replace(newSignature, lStr, asUpper, -1)
	}

	return newSignature
}

func TestHMACAuthSessionPassWithHeaderFieldLowerCase(t *testing.T) {
	spec := createSpecTest(t, hmacAuthDef)
	session := createHMACAuthSession()

	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("9876", session, 60)

	recorder := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/", nil)

	refDate := "Mon, 02 Jan 2006 15:04:05 MST"

	// Signature needs to be: Authorization: Signature keyId="hmac-key-1",algorithm="hmac-sha1",signature="Base64(HMAC-SHA1(signing string))"

	// Prep the signature string
	tim := time.Now().Format(refDate)
	req.Header.Add("Date", tim)
	req.Header.Add("X-Test-1", "hello?")
	req.Header.Add("X-Test-2", "world£")
	signatureString := strings.ToLower("(request-target): ") + "get /\n"
	signatureString += strings.ToLower("Date") + ": " + tim + "\n"
	signatureString += strings.ToLower("X-Test-1") + ": " + "hello?" + "\n"
	signatureString += strings.ToLower("X-Test-2") + ": " + "world£"

	// Encode it
	key := []byte(session.HmacSecret)
	h := hmac.New(sha1.New, key)
	h.Write([]byte(signatureString))

	sigString := base64.StdEncoding.EncodeToString(h.Sum(nil))
	encodedString := url.QueryEscape(sigString)

	_, upperCaseList := getUpperCaseEscaped(encodedString)
	newEncodedSignature := replaceUpperCase(encodedString, upperCaseList)

	req.Header.Add("Authorization", fmt.Sprintf("Signature keyId=\"9876\",algorithm=\"hmac-sha1\",headers=\"(request-target) date x-test-1 x-test-2\",signature=\"%s\"", newEncodedSignature))

	if err != nil {
		t.Fatal(err)
	}

	chain := getHMACAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
	}
}

package gateway

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/justinas/alice"
	"github.com/lonelycode/go-uuid/uuid"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/user"
)

const hmacAuthDef = `{
	"api_id": "1",
	"org_id": "default",
	"enable_signature_checking": true,
	"hmac_allowed_clock_skew": 5000,
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {"name": "v1"}
		}
	},
	"proxy": {
		"listen_path": "/v1",
		"target_url": "` + testHttpAny + `"
	}
}`

func createHMACAuthSession() *user.SessionState {
	session := new(user.SessionState)
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
	baseMid := BaseMiddleware{Spec: spec, Proxy: proxy}
	chain := alice.New(mwList(
		&IPWhiteListMiddleware{baseMid},
		&IPBlackListMiddleware{BaseMiddleware: baseMid},
		&HMACMiddleware{BaseMiddleware: baseMid},
		&VersionCheck{BaseMiddleware: baseMid},
		&KeyExpired{baseMid},
		&AccessRightsCheck{baseMid},
		&RateLimitAndQuotaCheck{baseMid},
	)...).Then(proxyHandler)
	return chain
}

type testAuthFailEventHandler struct {
	cb func(config.EventMessage)
}

func (w *testAuthFailEventHandler) Init(handlerConf interface{}) error {
	return nil
}

func (w *testAuthFailEventHandler) HandleEvent(em config.EventMessage) {
	w.cb(em)
}

func waitTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return false // completed normally
	case <-time.After(timeout):
		return true // timed out
	}
}

func testPrepareHMACAuthSessionPass(tb testing.TB, hashFn func() hash.Hash, eventWG *sync.WaitGroup, withHeader bool, isBench bool) (string, *APISpec, *http.Request, string) {
	spec := createSpecTest(tb, hmacAuthDef)
	session := createHMACAuthSession()

	// Should not receive an AuthFailure event
	cb := func(em config.EventMessage) {
		eventWG.Done()
	}
	spec.EventPaths = map[apidef.TykEvent][]config.TykEventHandler{
		"AuthFailure": {&testAuthFailEventHandler{cb}},
	}

	sessionKey := ""
	if isBench {
		sessionKey = uuid.New()
	} else {
		sessionKey = "9876"
	}

	spec.SessionManager.UpdateSession(sessionKey, session, 60, false)

	req := testReq(tb, "GET", "/", nil)

	refDate := "Mon, 02 Jan 2006 15:04:05 MST"

	// Signature needs to be: Authorization: Signature keyId="hmac-key-1",algorithm="hmac-sha1",signature="Base64(HMAC-SHA1(signing string))"

	// Prep the signature string
	tim := time.Now().Format(refDate)
	req.Header.Set("Date", tim)
	signatureString := ""
	if withHeader {
		req.Header.Set("X-Test-1", "hello")
		req.Header.Set("X-Test-2", "world")
		signatureString = strings.ToLower("(request-target): ") + "get /\n"
		signatureString += strings.ToLower("Date") + ": " + tim + "\n"
		signatureString += strings.ToLower("X-Test-1") + ": " + "hello" + "\n"
		signatureString += strings.ToLower("X-Test-2") + ": " + "world"
	} else {
		signatureString = strings.ToLower("Date") + ": " + tim
	}

	// Encode it
	key := []byte(session.HmacSecret)
	h := hmac.New(hashFn, key)
	h.Write([]byte(signatureString))

	sigString := base64.StdEncoding.EncodeToString(h.Sum(nil))
	encodedString := url.QueryEscape(sigString)

	return encodedString, spec, req, sessionKey
}

func TestHMACAuthSessionPass(t *testing.T) {
	// Should not receive an AuthFailure event
	var eventWG sync.WaitGroup
	eventWG.Add(1)
	encodedString, spec, req, sessionKey := testPrepareHMACAuthSessionPass(t, sha1.New, &eventWG, false, false)

	recorder := httptest.NewRecorder()
	req.Header.Set("Authorization", fmt.Sprintf("Signature keyId=\"%s\",algorithm=\"hmac-sha1\",signature=\"%s\"", sessionKey, encodedString))

	chain := getHMACAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code, recorder.Body.String())
	}

	// Check we did not get our AuthFailure event
	if !waitTimeout(&eventWG, 20*time.Millisecond) {
		t.Error("Request should not have generated an AuthFailure event!: \n")
	}
}

func TestHMACAuthSessionSHA512Pass(t *testing.T) {
	// Should not receive an AuthFailure event
	var eventWG sync.WaitGroup
	eventWG.Add(1)
	encodedString, spec, req, sessionKey := testPrepareHMACAuthSessionPass(t, sha512.New, &eventWG, false, false)

	recorder := httptest.NewRecorder()
	req.Header.Set("Authorization", fmt.Sprintf("Signature keyId=\"%s\",algorithm=\"hmac-sha512\",signature=\"%s\"", sessionKey, encodedString))

	spec.HmacAllowedAlgorithms = []string{"hmac-sha512"}
	chain := getHMACAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code, recorder.Body.String())
	}

	// Check we did not get our AuthFailure event
	if !waitTimeout(&eventWG, 20*time.Millisecond) {
		t.Error("Request should not have generated an AuthFailure event!: \n")
	}
}

func BenchmarkHMACAuthSessionPass(b *testing.B) {
	b.ReportAllocs()

	var eventWG sync.WaitGroup
	eventWG.Add(b.N)
	encodedString, spec, req, sessionKey := testPrepareHMACAuthSessionPass(b, sha1.New, &eventWG, false, true)

	recorder := httptest.NewRecorder()
	req.Header.Set("Authorization", fmt.Sprintf("Signature keyId=\"%s\",algorithm=\"hmac-sha1\",signature=\"%s\"", sessionKey, encodedString))

	chain := getHMACAuthChain(spec)

	for i := 0; i < b.N; i++ {
		chain.ServeHTTP(recorder, req)
		if recorder.Code != 200 {
			b.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code, recorder.Body.String())
		}
	}
}

func TestHMACAuthSessionAuxDateHeader(t *testing.T) {
	spec := createSpecTest(t, hmacAuthDef)
	session := createHMACAuthSession()

	// Should not receive an AuthFailure event
	var eventWG sync.WaitGroup
	eventWG.Add(1)
	cb := func(em config.EventMessage) {
		eventWG.Done()
	}
	spec.EventPaths = map[apidef.TykEvent][]config.TykEventHandler{
		"AuthFailure": {&testAuthFailEventHandler{cb}},
	}

	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("9876", session, 60, false)

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/", nil)

	refDate := "Mon, 02 Jan 2006 15:04:05 MST"

	// Signature needs to be: Authorization: Signature keyId="hmac-key-1",algorithm="hmac-sha1",signature="Base64(HMAC-SHA1(signing string))"

	// Prep the signature string
	tim := time.Now().Format(refDate)
	req.Header.Set("x-aux-date", tim)
	signatureString := strings.ToLower("x-aux-date") + ": " + tim

	// Encode it
	key := []byte(session.HmacSecret)
	h := hmac.New(sha1.New, key)
	h.Write([]byte(signatureString))

	sigString := base64.StdEncoding.EncodeToString(h.Sum(nil))
	encodedString := url.QueryEscape(sigString)

	req.Header.Set("Authorization", fmt.Sprintf("Signature keyId=\"9876\",algorithm=\"hmac-sha1\",signature=\"%s\"", encodedString))

	chain := getHMACAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
	}

	// Check we did not get our AuthFailure event
	if !waitTimeout(&eventWG, 20*time.Millisecond) {
		t.Error("Request should not have generated an AuthFailure event!: \n")
	}
}

func TestHMACAuthSessionFailureDateExpired(t *testing.T) {
	spec := createSpecTest(t, hmacAuthDef)
	session := createHMACAuthSession()

	// Should receive an AuthFailure event
	var eventWG sync.WaitGroup
	eventWG.Add(1)
	cb := func(em config.EventMessage) {
		eventWG.Done()
	}
	spec.EventPaths = map[apidef.TykEvent][]config.TykEventHandler{
		"AuthFailure": {&testAuthFailEventHandler{cb}},
	}

	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("9876", session, 60, false)

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/", nil)

	refDate := "Mon, 02 Jan 2006 15:04:05 MST"

	// Signature needs to be: Authorization: Signature keyId="hmac-key-1",algorithm="hmac-sha1",signature="Base64(HMAC-SHA1(signing string))"

	// Prep the signature string
	tim := time.Now().Format(refDate)
	req.Header.Set("Date", tim)
	signatureString := strings.ToLower("Date") + ":" + tim

	// Encode it
	key := []byte(session.HmacSecret)
	h := hmac.New(sha1.New, key)
	h.Write([]byte(signatureString))

	sigString := base64.StdEncoding.EncodeToString(h.Sum(nil))
	encodedString := url.QueryEscape(sigString)

	req.Header.Set("Authorization", fmt.Sprintf("Signature keyId=\"9876\",algorithm=\"hmac-sha1\",signature=\"%s\"", encodedString))

	chain := getHMACAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 400 {
		t.Error("Request should have failed with out of date error!: \n", recorder.Code)
	}

	// Check we did get our AuthFailure event
	if waitTimeout(&eventWG, 20*time.Millisecond) {
		t.Error("Request should have generated an AuthFailure event!: \n")
	}
}

func TestHMACAuthSessionKeyMissing(t *testing.T) {
	spec := createSpecTest(t, hmacAuthDef)
	session := createHMACAuthSession()

	// Should receive an AuthFailure event
	var eventWG sync.WaitGroup
	eventWG.Add(1)
	cb := func(em config.EventMessage) {
		eventWG.Done()
	}
	spec.EventPaths = map[apidef.TykEvent][]config.TykEventHandler{
		"AuthFailure": {&testAuthFailEventHandler{cb}},
	}

	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("9876", session, 60, false)

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/", nil)

	refDate := "Mon, 02 Jan 2006 15:04:05 MST"

	// Signature needs to be: Authorization: Signature keyId="hmac-key-1",algorithm="hmac-sha1",signature="Base64(HMAC-SHA1(signing string))"

	// Prep the signature string
	tim := time.Now().Format(refDate)
	req.Header.Set("Date", tim)
	signatureString := strings.ToLower("Date") + ":" + tim

	// Encode it
	key := []byte(session.HmacSecret)
	h := hmac.New(sha1.New, key)
	h.Write([]byte(signatureString))

	sigString := base64.StdEncoding.EncodeToString(h.Sum(nil))
	encodedString := url.QueryEscape(sigString)

	req.Header.Set("Authorization", fmt.Sprintf("Signature keyId=\"98765\",algorithm=\"hmac-sha1\",signature=\"%s\"", encodedString))

	chain := getHMACAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 400 {
		t.Error("Request should have failed with key not found error!: \n", recorder.Code)
	}

	// Check we did get our AuthFailure event
	if waitTimeout(&eventWG, 20*time.Millisecond) {
		t.Error("Request should have generated an AuthFailure event!: \n")
	}
}

func TestHMACAuthSessionMalformedHeader(t *testing.T) {
	spec := createSpecTest(t, hmacAuthDef)
	session := createHMACAuthSession()

	// Should receive an AuthFailure event
	var eventWG sync.WaitGroup
	eventWG.Add(1)
	cb := func(em config.EventMessage) {
		eventWG.Done()
	}
	spec.EventPaths = map[apidef.TykEvent][]config.TykEventHandler{
		"AuthFailure": {&testAuthFailEventHandler{cb}},
	}

	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("9876", session, 60, false)

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/", nil)

	refDate := "Mon, 02 Jan 2006 15:04:05 MST"

	// Signature needs to be: Authorization: Signature keyId="hmac-key-1",algorithm="hmac-sha1",signature="Base64(HMAC-SHA1(signing string))"

	// Prep the signature string
	tim := time.Now().Format(refDate)
	req.Header.Set("Date", tim)
	signatureString := strings.ToLower("Date") + ":" + tim

	// Encode it
	key := []byte(session.HmacSecret)
	h := hmac.New(sha1.New, key)
	h.Write([]byte(signatureString))

	sigString := base64.StdEncoding.EncodeToString(h.Sum(nil))
	encodedString := url.QueryEscape(sigString)

	req.Header.Set("Authorization", fmt.Sprintf("Signature keyID=\"98765\", algorithm=\"hmac-sha256\", signature=\"%s\"", encodedString))

	chain := getHMACAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 400 {
		t.Error("Request should have failed with key not found error!: \n", recorder.Code)
	}

	// Check we did get our AuthFailure event
	if waitTimeout(&eventWG, 20*time.Millisecond) {
		t.Error("Request should have generated an AuthFailure event!: \n")
	}
}

func TestHMACAuthSessionPassWithHeaderField(t *testing.T) {
	// Should not receive an AuthFailure event
	var eventWG sync.WaitGroup
	eventWG.Add(1)
	encodedString, spec, req, sessionKey := testPrepareHMACAuthSessionPass(t, sha1.New, &eventWG, true, false)

	recorder := httptest.NewRecorder()
	req.Header.Set("Authorization", fmt.Sprintf("Signature keyId=\"%s\",algorithm=\"hmac-sha1\",headers=\"(request-target) date x-test-1 x-test-2\",signature=\"%s\"", sessionKey, encodedString))

	chain := getHMACAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
	}

	// Check we did not get our AuthFailure event
	if !waitTimeout(&eventWG, 20*time.Millisecond) {
		t.Error("Request should not have generated an AuthFailure event!: \n")
	}
}

func BenchmarkHMACAuthSessionPassWithHeaderField(b *testing.B) {
	b.ReportAllocs()

	var eventWG sync.WaitGroup
	eventWG.Add(b.N)
	encodedString, spec, req, sessionKey := testPrepareHMACAuthSessionPass(b, sha1.New, &eventWG, true, true)

	recorder := httptest.NewRecorder()
	req.Header.Set("Authorization", fmt.Sprintf("Signature keyId=\"%s\",algorithm=\"hmac-sha1\",headers=\"(request-target) date x-test-1 x-test-2\",signature=\"%s\"", sessionKey, encodedString))

	chain := getHMACAuthChain(spec)

	for i := 0; i < b.N; i++ {
		chain.ServeHTTP(recorder, req)
		if recorder.Code != 200 {
			b.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
		}
	}
}

func getUpperCaseEscaped(signature string) []string {
	r := regexp.MustCompile(`%[A-F0-9][A-F0-9]`)
	foundList := r.FindAllString(signature, -1)
	return foundList
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

	// Should not receive an AuthFailure event
	var eventWG sync.WaitGroup
	eventWG.Add(1)
	cb := func(em config.EventMessage) {
		eventWG.Done()
	}
	spec.EventPaths = map[apidef.TykEvent][]config.TykEventHandler{
		"AuthFailure": {&testAuthFailEventHandler{cb}},
	}

	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("9876", session, 60, false)

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/", nil)

	refDate := "Mon, 02 Jan 2006 15:04:05 MST"

	// Signature needs to be: Authorization: Signature keyId="hmac-key-1",algorithm="hmac-sha1",signature="Base64(HMAC-SHA1(signing string))"

	// Prep the signature string
	tim := time.Now().Format(refDate)
	req.Header.Set("Date", tim)
	req.Header.Set("X-Test-1", "hello?")
	req.Header.Set("X-Test-2", "world£")
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

	upperCaseList := getUpperCaseEscaped(encodedString)
	newEncodedSignature := replaceUpperCase(encodedString, upperCaseList)

	req.Header.Set("Authorization", fmt.Sprintf("Signature keyId=\"9876\",algorithm=\"hmac-sha1\",headers=\"(request-target) date x-test-1 x-test-2\",signature=\"%s\"", newEncodedSignature))

	chain := getHMACAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
	}

	// Check we did not get our AuthFailure event
	if !waitTimeout(&eventWG, 20*time.Millisecond) {
		t.Error("Request should not have generated an AuthFailure event!: \n")
	}
}

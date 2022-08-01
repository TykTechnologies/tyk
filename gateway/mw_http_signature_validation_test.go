package gateway

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
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

	"github.com/TykTechnologies/tyk/certs"

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
		"target_url": "` + TestHttpAny + `"
	}
}`

func createHMACAuthSession() *user.SessionState {
	session := user.NewSessionState()
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

func createRSAAuthSession(pubCertId string) *user.SessionState {
	session := user.NewSessionState()
	session.Rate = 8.0
	session.Allowance = session.Rate
	session.LastCheck = time.Now().Unix()
	session.Per = 1.0
	session.QuotaRenewalRate = 300 // 5 minutes
	session.QuotaRenews = time.Now().Unix() + 20
	session.QuotaRemaining = 1
	session.QuotaMax = -1
	session.EnableHTTPSignatureValidation = true
	session.RSACertificateId = pubCertId
	return session
}

func (ts *Test) getHMACAuthChain(spec *APISpec) http.Handler {

	remote, _ := url.Parse(TestHttpAny)
	proxy := ts.Gw.TykNewSingleHostReverseProxy(remote, spec, nil)
	proxyHandler := ProxyHandler(proxy, spec)
	baseMid := BaseMiddleware{Spec: spec, Proxy: proxy, Gw: ts.Gw}
	chain := alice.New(ts.Gw.mwList(
		&IPWhiteListMiddleware{baseMid},
		&IPBlackListMiddleware{BaseMiddleware: baseMid},
		&HTTPSignatureValidationMiddleware{BaseMiddleware: baseMid},
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

func testPrepareHMACAuthSessionPass(tb testing.TB, ts *Test, hashFn func() hash.Hash, eventWG *sync.WaitGroup, withHeader bool, isBench bool) (string, *APISpec, *http.Request, string) {
	spec := ts.Gw.LoadSampleAPI(hmacAuthDef)

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

	err := ts.Gw.GlobalSessionManager.UpdateSession(sessionKey, session, 60, false)
	if err != nil {
		tb.Error("could not update session in Session Manager. " + err.Error())
	}

	req := TestReq(tb, "GET", "/", nil)

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

func testPrepareRSAAuthSessionPass(tb testing.TB, eventWG *sync.WaitGroup, privateKey *rsa.PrivateKey, pubCertId string, withHeader bool, isBench bool, ts *Test) (string, *APISpec, *http.Request, string) {

	spec := ts.Gw.LoadSampleAPI(hmacAuthDef)
	session := createRSAAuthSession(pubCertId)

	// Should not receive an AuthFailure event
	cb := func(em config.EventMessage) {
		eventWG.Done()
	}
	spec.EventPaths = map[apidef.TykEvent][]config.TykEventHandler{
		EventAuthFailure: {&testAuthFailEventHandler{cb}},
	}

	sessionKey := ""
	if isBench {
		sessionKey = uuid.New()
	} else {
		sessionKey = "9876"
	}

	err := ts.Gw.GlobalSessionManager.UpdateSession(sessionKey, session, 60, false)
	if err != nil {
		tb.Error("could not update session in Session Manager. " + err.Error())
	}

	req := TestReq(tb, "GET", "/", nil)

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

	h := sha256.New()
	h.Write([]byte(signatureString))
	hashed := h.Sum(nil)

	signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)

	sigString := base64.StdEncoding.EncodeToString(signature)

	return sigString, spec, req, sessionKey
}

func TestHMACAuthSessionPass(t *testing.T) {

	// Should not receive an AuthFailure event
	var eventWG sync.WaitGroup
	eventWG.Add(1)

	ts := StartTest(nil)
	defer ts.Close()

	encodedString, spec, req, sessionKey := testPrepareHMACAuthSessionPass(t, ts, sha1.New, &eventWG, false, false)

	recorder := httptest.NewRecorder()
	req.Header.Set("Authorization", fmt.Sprintf("Signature keyId=\"%s\",algorithm=\"hmac-sha1\",signature=\"%s\"", sessionKey, encodedString))

	chain := ts.getHMACAuthChain(spec)
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

	ts := StartTest(nil)
	defer ts.Close()

	encodedString, spec, req, sessionKey := testPrepareHMACAuthSessionPass(t, ts, sha512.New, &eventWG, false, false)

	recorder := httptest.NewRecorder()
	req.Header.Set("Authorization", fmt.Sprintf("Signature keyId=\"%s\",algorithm=\"hmac-sha512\",signature=\"%s\"", sessionKey, encodedString))

	spec.HmacAllowedAlgorithms = []string{"hmac-sha512"}
	chain := ts.getHMACAuthChain(spec)
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

	ts := StartTest(nil)
	defer ts.Close()

	encodedString, spec, req, sessionKey := testPrepareHMACAuthSessionPass(b, ts, sha1.New, &eventWG, false, true)

	recorder := httptest.NewRecorder()
	req.Header.Set("Authorization", fmt.Sprintf("Signature keyId=\"%s\",algorithm=\"hmac-sha1\",signature=\"%s\"", sessionKey, encodedString))

	chain := ts.getHMACAuthChain(spec)

	for i := 0; i < b.N; i++ {
		chain.ServeHTTP(recorder, req)
		if recorder.Code != 200 {
			b.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code, recorder.Body.String())
		}
	}
}

func TestHMACAuthSessionAuxDateHeader(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	spec := ts.Gw.LoadSampleAPI(hmacAuthDef)

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
	err := ts.Gw.GlobalSessionManager.UpdateSession("9876", session, 60, false)
	if err != nil {
		t.Error("could not update session in Session Manager. " + err.Error())
	}

	recorder := httptest.NewRecorder()
	req := TestReq(t, "GET", "/", nil)

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

	chain := ts.getHMACAuthChain(spec)
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
	ts := StartTest(nil)
	defer ts.Close()

	spec := ts.Gw.LoadSampleAPI(hmacAuthDef)
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
	err := ts.Gw.GlobalSessionManager.UpdateSession("9876", session, 60, false)
	if err != nil {
		t.Error("could not update session in Session Manager. " + err.Error())
	}

	recorder := httptest.NewRecorder()
	req := TestReq(t, "GET", "/", nil)

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

	chain := ts.getHMACAuthChain(spec)
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
	ts := StartTest(nil)
	defer ts.Close()

	spec := ts.Gw.LoadSampleAPI(hmacAuthDef)
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
	err := ts.Gw.GlobalSessionManager.UpdateSession("9876", session, 60, false)
	if err != nil {
		t.Error("could not update session in Session Manager. " + err.Error())
	}

	recorder := httptest.NewRecorder()
	req := TestReq(t, "GET", "/", nil)

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

	chain := ts.getHMACAuthChain(spec)
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
	ts := StartTest(nil)
	defer ts.Close()

	spec := ts.Gw.LoadSampleAPI(hmacAuthDef)
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
	err := ts.Gw.GlobalSessionManager.UpdateSession("9876", session, 60, false)
	if err != nil {
		t.Error("could not update session in Session Manager. " + err.Error())
	}

	recorder := httptest.NewRecorder()
	req := TestReq(t, "GET", "/", nil)

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

	chain := ts.getHMACAuthChain(spec)
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

	ts := StartTest(nil)
	defer ts.Close()

	encodedString, spec, req, sessionKey := testPrepareHMACAuthSessionPass(t, ts, sha1.New, &eventWG, true, false)

	recorder := httptest.NewRecorder()
	req.Header.Set("Authorization", fmt.Sprintf("Signature keyId=\"%s\",algorithm=\"hmac-sha1\",headers=\"(request-target) date x-test-1 x-test-2\",signature=\"%s\"", sessionKey, encodedString))

	chain := ts.getHMACAuthChain(spec)
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

	ts := StartTest(nil)
	defer ts.Close()

	encodedString, spec, req, sessionKey := testPrepareHMACAuthSessionPass(b, ts, sha1.New, &eventWG, true, true)

	recorder := httptest.NewRecorder()
	req.Header.Set("Authorization", fmt.Sprintf("Signature keyId=\"%s\",algorithm=\"hmac-sha1\",headers=\"(request-target) date x-test-1 x-test-2\",signature=\"%s\"", sessionKey, encodedString))

	chain := ts.getHMACAuthChain(spec)

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
	ts := StartTest(nil)
	defer ts.Close()

	spec := ts.Gw.LoadSampleAPI(hmacAuthDef)
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
	err := ts.Gw.GlobalSessionManager.UpdateSession("9876", session, 60, false)
	if err != nil {
		t.Error("could not update session in Session Manager. " + err.Error())
	}

	recorder := httptest.NewRecorder()
	req := TestReq(t, "GET", "/", nil)

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

	chain := ts.getHMACAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
	}

	// Check we did not get our AuthFailure event
	if !waitTimeout(&eventWG, 20*time.Millisecond) {
		t.Error("Request should not have generated an AuthFailure event!: \n")
	}
}

func TestGetFieldValues(t *testing.T) {
	key := `eyJvcmciOiI1ZDgzOTczNDk4NThkYzEwYWU3NjA2ZjQiLCJpZCI6ImU2M2M2MTg4ZjFlYzQ2NzU4N2VlMTA1MzZkYmFjMzk0IiwiaCI6Im11cm11cjY0In0=`
	algo := `hmac-sha1`
	sign := `j27%2FQtZHmlQuWmnQT%2BxLjHcgPl8%3D`
	s := `KeyId="eyJvcmciOiI1ZDgzOTczNDk4NThkYzEwYWU3NjA2ZjQiLCJpZCI6ImU2M2M2MTg4ZjFlYzQ2NzU4N2VlMTA1MzZkYmFjMzk0IiwiaCI6Im11cm11cjY0In0=",algorithm="hmac-sha1",signature="j27%2FQtZHmlQuWmnQT%2BxLjHcgPl8%3D"`
	h, err := getFieldValues(s)
	if err != nil {
		t.Fatal(err)
	}
	if h.KeyID != key {
		t.Errorf("expected keyID:%s got %s", key, h.KeyID)
	}
	if h.Algorthm != algo {
		t.Errorf("expected Algorithm:%s got %s", algo, h.Algorthm)
	}
	if h.Signature != sign {
		t.Errorf("expected Signature:%s got %s", sign, h.Signature)
	}
}

func TestRSAAuthSessionPass(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	_, _, _, serverCert := certs.GenServerCertificate()
	privateKey := serverCert.PrivateKey.(*rsa.PrivateKey)
	x509Cert, _ := x509.ParseCertificate(serverCert.Certificate[0])
	pubDer, _ := x509.MarshalPKIXPublicKey(x509Cert.PublicKey)
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer})
	pubID, _ := ts.Gw.CertificateManager.Add(pubPem, "")
	defer ts.Gw.CertificateManager.Delete(pubID, "")

	// Should not receive an AuthFailure event
	var eventWG sync.WaitGroup
	eventWG.Add(1)
	encodedString, spec, req, sessionKey := testPrepareRSAAuthSessionPass(t, &eventWG, privateKey, pubID, false, false, ts)

	recorder := httptest.NewRecorder()
	req.Header.Set("Authorization", fmt.Sprintf("Signature keyId=\"%s\",algorithm=\"rsa-sha256\",signature=\"%s\"", sessionKey, encodedString))

	chain := ts.getHMACAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code, recorder.Body.String())
	}

	// Check we did not get our AuthFailure event
	if !waitTimeout(&eventWG, 20*time.Millisecond) {
		t.Error("Request should not have generated an AuthFailure event!: \n")
	}
}

func BenchmarkRSAAuthSessionPass(b *testing.B) {
	b.ReportAllocs()

	ts := StartTest(nil)
	defer ts.Close()

	_, _, _, serverCert := certs.GenServerCertificate()
	privateKey := serverCert.PrivateKey.(*rsa.PrivateKey)
	x509Cert, _ := x509.ParseCertificate(serverCert.Certificate[0])
	pubDer, _ := x509.MarshalPKIXPublicKey(x509Cert.PublicKey)
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer})
	pubID, _ := ts.Gw.CertificateManager.Add(pubPem, "")
	defer ts.Gw.CertificateManager.Delete(pubID, "")

	var eventWG sync.WaitGroup
	eventWG.Add(b.N)
	encodedString, spec, req, sessionKey := testPrepareRSAAuthSessionPass(b, &eventWG, privateKey, pubID, false, true, ts)

	recorder := httptest.NewRecorder()
	req.Header.Set("Authorization", fmt.Sprintf("Signature keyId=\"%s\",algorithm=\"rsa-sha256\",signature=\"%s\"", sessionKey, encodedString))

	chain := ts.getHMACAuthChain(spec)

	for i := 0; i < b.N; i++ {
		chain.ServeHTTP(recorder, req)
		if recorder.Code != 200 {
			b.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code, recorder.Body.String())
		}
	}
}

func TestRSAAuthSessionKeyMissing(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	_, _, _, serverCert := certs.GenServerCertificate()
	privateKey := serverCert.PrivateKey.(*rsa.PrivateKey)
	x509Cert, _ := x509.ParseCertificate(serverCert.Certificate[0])
	pubDer, _ := x509.MarshalPKIXPublicKey(x509Cert.PublicKey)
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer})
	pubID, _ := ts.Gw.CertificateManager.Add(pubPem, "")
	defer ts.Gw.CertificateManager.Delete(pubID, "")

	// Should receive an AuthFailure events
	var eventWG sync.WaitGroup
	eventWG.Add(1)

	recorder := httptest.NewRecorder()
	encodedString, spec, req, _ := testPrepareRSAAuthSessionPass(t, &eventWG, privateKey, pubID, false, false, ts)

	req.Header.Set("Authorization", fmt.Sprintf("Signature keyId=\"98765\",algorithm=\"rsa-sha256\",signature=\"%s\"", encodedString))

	chain := ts.getHMACAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 400 {
		t.Error("Request should have failed with key not found error!: \n", recorder.Code)
	}

	// Check we did get our AuthFailure event
	if waitTimeout(&eventWG, 20*time.Millisecond) {
		t.Error("Request should have generated an AuthFailure event!: \n")
	}
}

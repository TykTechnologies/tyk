package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/garyburd/redigo/redis"
	"github.com/gorilla/mux"

	"github.com/TykTechnologies/tyk/apidef"
)

const apiTestDef = `{
	"api_id": "1",
	"org_id": "default",
	"definition": {
		"location": "header",
		"key": "version"
	},
	"auth": {
		"auth_header_name": "authorization"
	},
	"version_data": {
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

func loadSampleAPI(t *testing.T, def string) {
	spec := createSpecTest(t, def)
	loadApps([]*APISpec{spec}, discardMuxer)
}

type testAPIDefinition struct {
	apidef.APIDefinition
	ID string `json:"id"`
}

func TestHealthCheckEndpoint(t *testing.T) {
	uri := "/tyk/health/?api_id=1"

	recorder := httptest.NewRecorder()
	loadSampleAPI(t, apiTestDef)

	req := testReq(t, "GET", uri, nil)

	healthCheckhandler(recorder, req)
	if recorder.Code != 200 {
		t.Error("Recorder should return 200 for health check")
	}
}

func createSampleSession() *SessionState {
	return &SessionState{
		Rate:             5.0,
		Allowance:        5.0,
		LastCheck:        time.Now().Unix(),
		Per:              8.0,
		QuotaRenewalRate: 300, // 5 minutes
		QuotaRenews:      time.Now().Unix(),
		QuotaRemaining:   10,
		QuotaMax:         10,
		AccessRights: map[string]AccessDefinition{
			"1": {
				APIName:  "Test",
				APIID:    "1",
				Versions: []string{"Default"},
			},
		},
	}
}

func TestApiHandler(t *testing.T) {
	uris := []string{"/tyk/apis/", "/tyk/apis"}

	for _, uri := range uris {
		sampleKey := createSampleSession()
		recorder := httptest.NewRecorder()

		loadSampleAPI(t, apiTestDef)

		req := withAuth(testReq(t, "GET", uri, sampleKey))

		mainRouter.ServeHTTP(recorder, req)

		// We can't deserialize BSON ObjectID's if they are not in th test base!
		var apiList []testAPIDefinition
		json.NewDecoder(recorder.Body).Decode(&apiList)

		if len(apiList) != 1 {
			t.Error("API's not returned, len was: \n", len(apiList), recorder.Body.String(), uri)
		} else if apiList[0].APIID != "1" {
			t.Error("Response is incorrect - no API ID value in struct :\n", recorder.Body.String(), uri)
		}
	}
}

func TestApiHandlerGetSingle(t *testing.T) {
	uri := "/tyk/apis/1"
	sampleKey := createSampleSession()

	recorder := httptest.NewRecorder()

	loadSampleAPI(t, apiTestDef)

	req := withAuth(testReq(t, "GET", uri, sampleKey))

	mainRouter.ServeHTTP(recorder, req)

	// We can't deserialize BSON ObjectID's if they are not in th test base!
	var apiDef testAPIDefinition
	json.NewDecoder(recorder.Body).Decode(&apiDef)

	if apiDef.APIID != "1" {
		t.Error("Response is incorrect - no API ID value in struct :\n", recorder.Body.String())
	}
}

func TestApiHandlerPost(t *testing.T) {
	uri := "/tyk/apis/1"
	recorder := httptest.NewRecorder()

	req := withAuth(testReq(t, "POST", uri, apiTestDef))

	mainRouter.ServeHTTP(recorder, req)

	var success APIModifyKeySuccess
	json.NewDecoder(recorder.Body).Decode(&success)

	if success.Status != "ok" {
		t.Error("Response is incorrect - not success :\n", recorder.Body.String())
	}
}

func TestApiHandlerPostDupPath(t *testing.T) {
	specs := func() (res []*APISpec) {
		for _, id := range []string{"2", "3"} {
			def := strings.Replace(apiTestDef, `"1"`, `"`+id+`"`, 1)
			res = append(res, createSpecTest(t, def))
		}
		return res
	}
	var s2, s3 *APISpec

	// both dups added at the same time
	apisByID = nil
	loadApps(specs(), discardMuxer)

	s2 = apisByID["2"]
	if want, got := "/v1-2", s2.Proxy.ListenPath; want != got {
		t.Errorf("API spec %s want path %s, got %s", "2", want, got)
	}
	s3 = apisByID["3"]
	if want, got := "/v1-3", s3.Proxy.ListenPath; want != got {
		t.Errorf("API spec %s want path %s, got %s", "3", want, got)
	}

	// one dup was there first, gets to keep its path. apiids are
	// not used to mandate priority. survives multiple reloads too.
	apisByID = nil
	loadApps(specs()[1:], discardMuxer)
	loadApps(specs(), discardMuxer)
	loadApps(specs(), discardMuxer)

	s2 = apisByID["2"]
	if want, got := "/v1-2", s2.Proxy.ListenPath; want != got {
		t.Errorf("API spec %s want path %s, got %s", "2", want, got)
	}
	s3 = apisByID["3"]
	if want, got := "/v1", s3.Proxy.ListenPath; want != got {
		t.Errorf("API spec %s want path %s, got %s", "3", want, got)
	}

	// both dups were there first, neither gets to keep its original
	// path.
	apisByID = nil
	loadApps(specs(), discardMuxer)
	loadApps(specs(), discardMuxer)

	s2 = apisByID["2"]
	if want, got := "/v1-2", s2.Proxy.ListenPath; want != got {
		t.Errorf("API spec %s want path %s, got %s", "2", want, got)
	}
	s3 = apisByID["3"]
	if want, got := "/v1-3", s3.Proxy.ListenPath; want != got {
		t.Errorf("API spec %s want path %s, got %s", "3", want, got)
	}
}

func TestApiHandlerPostDbConfig(t *testing.T) {
	uri := "/tyk/apis/1"

	config.UseDBAppConfigs = true
	defer func() { config.UseDBAppConfigs = false }()

	recorder := httptest.NewRecorder()

	req := withAuth(testReq(t, "POST", uri, apiTestDef))

	mainRouter.ServeHTTP(recorder, req)

	var success APIModifyKeySuccess
	json.NewDecoder(recorder.Body).Decode(&success)
	if success.Status == "ok" {
		t.Error("Response is incorrect - expected error due to use_db_app_config :\n", recorder.Body.String())
	}
}

func TestApiHandlerMethodAPIID(t *testing.T) {
	base := "/tyk/apis"
	tests := [...]struct {
		method, path string
		code         int
	}{
		// GET and POST can do either
		{"GET", "/", 200},
		{"GET", "/missing", 404},
		{"POST", "/", 200},
		{"POST", "/1", 200},
		// DELETE and PUT must use one
		{"DELETE", "/1", 200},
		{"DELETE", "/", 400},
		{"PUT", "/1", 200},
		{"PUT", "/", 400},

		// apiid mismatch
		{"POST", "/mismatch", 400},
		{"PUT", "/mismatch", 400},
	}
	for _, tc := range tests {
		recorder := httptest.NewRecorder()
		url := base + tc.path
		req := withAuth(testReq(t, tc.method, url, apiTestDef))

		mainRouter.ServeHTTP(recorder, req)
		if tc.code != recorder.Code {
			t.Errorf("%s %s got %d, want %d", tc.method, url,
				recorder.Code, tc.code)
		}
	}
}

func TestKeyHandlerNewKey(t *testing.T) {
	for _, api_id := range []string{"1", "none", ""} {
		uri := "/tyk/keys/1234"
		sampleKey := createSampleSession()

		recorder := httptest.NewRecorder()
		param := make(url.Values)

		loadSampleAPI(t, apiTestDef)
		if api_id != "" {
			param.Set("api_id", api_id)
		}
		req := withAuth(testReq(t, "POST", uri+param.Encode(), sampleKey))

		mainRouter.ServeHTTP(recorder, req)

		newSuccess := APIModifyKeySuccess{}
		json.NewDecoder(recorder.Body).Decode(&newSuccess)
		if newSuccess.Status != "ok" {
			t.Error("key not created, status error:\n", recorder.Body.String())
		}
		if newSuccess.Action != "added" {
			t.Error("Response is incorrect - action is not 'added' :\n", recorder.Body.String())
		}
	}
}

func TestKeyHandlerUpdateKey(t *testing.T) {
	for _, api_id := range []string{"1", "none", ""} {
		uri := "/tyk/keys/1234"
		sampleKey := createSampleSession()

		recorder := httptest.NewRecorder()
		param := make(url.Values)
		loadSampleAPI(t, apiTestDef)
		if api_id != "" {
			param.Set("api_id", api_id)
		}
		req := withAuth(testReq(t, "PUT", uri+param.Encode(), sampleKey))

		mainRouter.ServeHTTP(recorder, req)

		newSuccess := APIModifyKeySuccess{}
		json.NewDecoder(recorder.Body).Decode(&newSuccess)
		if newSuccess.Status != "ok" {
			t.Error("key not created, status error:\n", recorder.Body.String())
		}
		if newSuccess.Action != "modified" {
			t.Error("Response is incorrect - action is not 'modified' :\n", recorder.Body.String())
		}
	}
}

func TestKeyHandlerGetKey(t *testing.T) {
	for _, api_id := range []string{"1", "none", ""} {
		loadSampleAPI(t, apiTestDef)
		createKey(t)

		uri := "/tyk/keys/1234"

		recorder := httptest.NewRecorder()
		param := make(url.Values)

		if api_id != "" {
			param.Set("api_id", api_id)
		}
		req := withAuth(testReq(t, "GET", uri+"?"+param.Encode(), nil))

		mainRouter.ServeHTTP(recorder, req)

		if recorder.Code != 200 {
			t.Error("key not requested, status error:\n", recorder.Body.String())
		}
	}
}

func createKey(t *testing.T) {
	uri := "/tyk/keys/1234"
	sampleKey := createSampleSession()

	recorder := httptest.NewRecorder()
	req := withAuth(testReq(t, "POST", uri, sampleKey))

	mainRouter.ServeHTTP(recorder, req)
}

func TestKeyHandlerDeleteKey(t *testing.T) {
	for _, api_id := range []string{"1", "none", ""} {
		createKey(t)

		uri := "/tyk/keys/1234?"

		recorder := httptest.NewRecorder()
		param := make(url.Values)
		loadSampleAPI(t, apiTestDef)
		if api_id != "" {
			param.Set("api_id", api_id)
		}
		req := withAuth(testReq(t, "DELETE", uri+param.Encode(), nil))

		mainRouter.ServeHTTP(recorder, req)

		newSuccess := APIModifyKeySuccess{}
		json.NewDecoder(recorder.Body).Decode(&newSuccess)

		if newSuccess.Status != "ok" {
			t.Error("key not deleted, status error:\n", recorder.Body.String())
		}
		if newSuccess.Action != "deleted" {
			t.Error("Response is incorrect - action is not 'deleted' :\n", recorder.Body.String())
		}
	}
}

func TestMethodNotSupported(t *testing.T) {
	recorder := httptest.NewRecorder()
	req := withAuth(testReq(t, "POST", "/tyk/reload/", nil))

	mainRouter.ServeHTTP(recorder, req)
	if recorder.Code != 405 {
		t.Fatal(`Wanted response to be 405 since the wrong method was used`)
	}
}

func TestCreateKeyHandlerCreateNewKey(t *testing.T) {
	for _, api_id := range []string{"1", "none", ""} {
		createKey(t)

		uri := "/tyk/keys/create"

		sampleKey := createSampleSession()

		recorder := httptest.NewRecorder()
		param := make(url.Values)
		loadSampleAPI(t, apiTestDef)
		if api_id != "" {
			param.Set("api_id", api_id)
		}
		req := withAuth(testReq(t, "POST", uri+param.Encode(), sampleKey))

		mainRouter.ServeHTTP(recorder, req)

		newSuccess := APIModifyKeySuccess{}
		json.NewDecoder(recorder.Body).Decode(&newSuccess)

		if newSuccess.Status != "ok" {
			t.Error("key not created, status error:\n", recorder.Body.String())
		}
		if newSuccess.Action != "added" {
			t.Error("Response is incorrect - action is not 'create' :\n", recorder.Body.String())
		}
	}
}

func TestAPIAuthFail(t *testing.T) {
	uri := "/tyk/health/?api_id=1"
	loadSampleAPI(t, apiTestDef)

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", uri, nil)
	req.Header.Set("x-tyk-authorization", "12345")

	mainRouter.ServeHTTP(recorder, req)

	if recorder.Code == 200 {
		t.Error("Access to API should have been blocked, but response code was: ", recorder.Code)
	}
}

func TestAPIAuthOk(t *testing.T) {
	uri := "/tyk/health/?api_id=1"

	recorder := httptest.NewRecorder()
	req := withAuth(testReq(t, "GET", uri, nil))

	loadSampleAPI(t, apiTestDef)
	mainRouter.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Access to API should have been blocked, but response code was: ", recorder.Code)
	}
}

func TestGetOAuthClients(t *testing.T) {
	testAPIID := "1"
	var responseCode int

	_, responseCode = getOauthClients(testAPIID)
	if responseCode != 400 {
		t.Fatal("Retrieving OAuth clients from nonexistent APIs must return error.")
	}

	apisByID = make(map[string]*APISpec)
	apisByID[testAPIID] = &APISpec{}

	_, responseCode = getOauthClients(testAPIID)
	if responseCode != 400 {
		t.Fatal("Retrieving OAuth clients from APIs with no OAuthManager must return an error.")
	}

	apisByID = nil
}

func TestResetHandler(t *testing.T) {
	apisByID = make(map[string]*APISpec)

	loadSampleAPI(t, apiTestDef)
	recorder := httptest.NewRecorder()

	req := testReq(t, "GET", "/tyk/reload", nil)
	var wg sync.WaitGroup
	wg.Add(1)
	resetHandler(wg.Done)(recorder, req)

	if recorder.Code != 200 {
		t.Fatal("Hot reload failed, response code was: ", recorder.Code)
	}
	reloadTick <- time.Time{}
	wg.Wait()

	if len(apisByID) == 0 {
		t.Fatal("Hot reload was triggered but no APIs were found.")
	}
}

func TestGroupResetHandler(t *testing.T) {
	didSubscribe := make(chan bool)
	didReload := make(chan bool)
	cacheStore := RedisClusterStorageManager{}
	cacheStore.Connect()

	go func() {
		err := cacheStore.StartPubSubHandler(RedisPubSubChannel, func(v interface{}) {
			switch x := v.(type) {
			case redis.Subscription:
				didSubscribe <- true
			case redis.Message:
				notf := Notification{}
				if err := json.Unmarshal(x.Data, &notf); err != nil {
					t.Fatal(err)
				}
				if notf.Command == NoticeGroupReload {
					didReload <- true
				}
			}
		})
		if err != nil {
			t.Log(err)
			t.Fail()
			close(didReload)
		}
	}()

	uri := "/tyk/reload/group"

	apisByID = make(map[string]*APISpec)

	loadSampleAPI(t, apiTestDef)

	recorder := httptest.NewRecorder()

	// If we don't wait for the subscription to be done, we might do
	// the reload before pub/sub is in place to receive our message.
	<-didSubscribe
	req := withAuth(testReq(t, "GET", uri, nil))

	mainRouter.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Fatal("Hot reload (group) failed, response code was: ", recorder.Code)
	}

	if len(apisByID) == 0 {
		t.Fatal("Hot reload (group) was triggered but no APIs were found.")
	}

	// We wait for the right notification (NoticeGroupReload), other
	// type of notifications may be received during tests, as this
	// is the cluster channel:
	<-didReload
}

func TestHotReloadSingle(t *testing.T) {
	oldRouter := mainRouter
	var wg sync.WaitGroup
	if !reloadURLStructure(wg.Done) {
		t.Fatal("reload wasn't queued")
	}
	wg.Add(1)
	reloadTick <- time.Time{}
	wg.Wait()
	if mainRouter == oldRouter {
		t.Fatal("router wasn't swapped")
	}
}

func TestHotReloadMany(t *testing.T) {
	done := 0
	var wg sync.WaitGroup
	// Spike of 25 reloads all at once, not giving any time for the
	// reload worker to pick up any of them. A single one is queued
	// and waits.
	for i := 0; i < 25; i++ {
		if reloadURLStructure(wg.Done) {
			wg.Add(1)
			done++
		}
	}
	if want := 1; done != want {
		t.Fatalf("wanted actual reloads to be %d, was %d", want, done)
	}
	// pick it up and finish it
	reloadTick <- time.Time{}
	wg.Wait()
	// 5 reloads, but this time slower - the reload worker has time
	// to do all of them.
	for i := 0; i < 5; i++ {
		if reloadURLStructure(wg.Done) {
			wg.Add(1)
			done++
		}
		// pick it up and finish it
		reloadTick <- time.Time{}
		wg.Wait()
	}
	if want := 6; done != want {
		t.Fatalf("wanted actual reloads to be %d, was %d", want, done)
	}
}

const apiBenchDef = `{
	"api_id": "REPLACE",
	"org_id": "default",
	"definition": {
		"location": "header",
		"key": "version"
	},
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
		"listen_path": "/listen-REPLACE",
		"target_url": "` + testHttpAny + `"
	}
}`

func BenchmarkApiReload(b *testing.B) {
	specs := make([]*APISpec, 1000)
	for i := range specs {
		id := strconv.Itoa(i + 1)
		def := strings.Replace(apiBenchDef, "REPLACE", id, -1)
		spec := createDefinitionFromString(def)
		specs[i] = spec
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		newMuxes := mux.NewRouter()
		loadAPIEndpoints(newMuxes)
		loadApps(specs, newMuxes)
	}
}

func TestContextData(t *testing.T) {
	r := new(http.Request)
	if ctxGetData(r) != nil {
		t.Fatal("expected ctxGetData to return nil")
	}
	ctxSetData(r, map[string]interface{}{"foo": "bar"})
	if ctxGetData(r) == nil {
		t.Fatal("expected ctxGetData to return non-nil")
	}
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected ctxSetData of zero val to panic")
		}
	}()
	ctxSetData(r, nil)
}

func TestContextSession(t *testing.T) {
	r := new(http.Request)
	if ctxGetSession(r) != nil {
		t.Fatal("expected ctxGetSession to return nil")
	}
	ctxSetSession(r, &SessionState{})
	if ctxGetSession(r) == nil {
		t.Fatal("expected ctxGetSession to return non-nil")
	}
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected ctxSetSession of zero val to panic")
		}
	}()
	ctxSetSession(r, nil)
}

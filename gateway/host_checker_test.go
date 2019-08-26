package gateway

import (
	"bytes"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"text/template"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
)

const sampleUptimeTestAPI = `{
	"api_id": "test",
	"use_keyless": true,
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {"name": "v1"}
		}
	},
	"uptime_tests": {
		"check_list": [
			{
				"url": "{{.Host1}}/get",
				"method": "GET"
			},
			{
				"url": "{{.Host2}}/get",
				"method": "GET"
			}
		]
	},
	"proxy": {
		"listen_path": "/",
		"enable_load_balancing": true,
		"check_host_against_uptime_tests": true,
		"target_list": [
			"{{.Host1}}",
			"{{.Host2}}"
		]
	}
}`

type testEventHandler struct {
	cb func(config.EventMessage)
}

func (w *testEventHandler) Init(handlerConf interface{}) error {
	return nil
}

func (w *testEventHandler) HandleEvent(em config.EventMessage) {
	w.cb(em)
}

func TestHostChecker(t *testing.T) {
	specTmpl := template.Must(template.New("spec").Parse(sampleUptimeTestAPI))

	tmplData := struct {
		Host1, Host2 string
	}{
		TestHttpAny,
		testHttpFailureAny,
	}

	specBuf := &bytes.Buffer{}
	specTmpl.ExecuteTemplate(specBuf, specTmpl.Name(), &tmplData)

	spec := CreateDefinitionFromString(specBuf.String())

	// From api_loader.go#processSpec
	sl := apidef.NewHostListFromList(spec.Proxy.Targets)
	spec.Proxy.StructuredTargetList = sl

	var eventWG sync.WaitGroup
	// Should receive one HostDown event
	eventWG.Add(1)
	cb := func(em config.EventMessage) {
		eventWG.Done()
	}

	spec.EventPaths = map[apidef.TykEvent][]config.TykEventHandler{
		"HostDown": {&testEventHandler{cb}},
	}

	apisMu.Lock()
	apisByID = map[string]*APISpec{spec.APIID: spec}
	apisMu.Unlock()
	GlobalHostChecker.checkerMu.Lock()
	GlobalHostChecker.checker.sampleTriggerLimit = 1
	GlobalHostChecker.checkerMu.Unlock()
	defer func() {
		apisMu.Lock()
		apisByID = make(map[string]*APISpec)
		apisMu.Unlock()
		GlobalHostChecker.checkerMu.Lock()
		GlobalHostChecker.checker.sampleTriggerLimit = defaultSampletTriggerLimit
		GlobalHostChecker.checkerMu.Unlock()
	}()

	SetCheckerHostList()
	GlobalHostChecker.checkerMu.Lock()
	if len(GlobalHostChecker.currentHostList) != 2 {
		t.Error("Should update hosts manager check list", GlobalHostChecker.currentHostList)
	}

	if len(GlobalHostChecker.checker.newList) != 2 {
		t.Error("Should update host checker check list")
	}
	GlobalHostChecker.checkerMu.Unlock()

	hostCheckTicker <- struct{}{}
	eventWG.Wait()

	if GlobalHostChecker.HostDown(TestHttpAny) {
		t.Error("Should not mark as down")
	}

	if !GlobalHostChecker.HostDown(testHttpFailureAny) {
		t.Error("Should mark as down")
	}

	// Test it many times concurrently, to simulate concurrent and
	// parallel requests to the API. This will catch bugs in those
	// scenarios, like data races.
	var targetWG sync.WaitGroup
	for i := 0; i < 10; i++ {
		targetWG.Add(1)
		go func() {
			host, err := nextTarget(spec.Proxy.StructuredTargetList, spec)
			if err != nil {
				t.Error("Should return nil error, got", err)
			}
			if host != TestHttpAny {
				t.Error("Should return only active host, got", host)
			}
			targetWG.Done()
		}()
	}
	targetWG.Wait()

	GlobalHostChecker.checkerMu.Lock()
	if GlobalHostChecker.checker.checkTimeout != defaultTimeout {
		t.Error("Should set defaults", GlobalHostChecker.checker.checkTimeout)
	}

	redisStore := GlobalHostChecker.store.(*storage.RedisCluster)
	if ttl, _ := redisStore.GetKeyTTL(PoolerHostSentinelKeyPrefix + testHttpFailure); int(ttl) != GlobalHostChecker.checker.checkTimeout*GlobalHostChecker.checker.sampleTriggerLimit {
		t.Error("HostDown expiration key should be checkTimeout + 1", ttl)
	}
	GlobalHostChecker.checkerMu.Unlock()
}

func TestReverseProxyAllDown(t *testing.T) {
	specTmpl := template.Must(template.New("spec").Parse(sampleUptimeTestAPI))

	tmplData := struct {
		Host1, Host2 string
	}{
		testHttpFailureAny,
		testHttpFailureAny,
	}

	specBuf := &bytes.Buffer{}
	specTmpl.ExecuteTemplate(specBuf, specTmpl.Name(), &tmplData)

	spec := CreateDefinitionFromString(specBuf.String())

	// From api_loader.go#processSpec
	sl := apidef.NewHostListFromList(spec.Proxy.Targets)
	spec.Proxy.StructuredTargetList = sl

	var eventWG sync.WaitGroup
	// Should receive one HostDown event
	eventWG.Add(1)
	cb := func(em config.EventMessage) {
		eventWG.Done()
	}
	spec.EventPaths = map[apidef.TykEvent][]config.TykEventHandler{
		"HostDown": {&testEventHandler{cb}},
	}

	apisMu.Lock()
	apisByID = map[string]*APISpec{spec.APIID: spec}
	apisMu.Unlock()
	GlobalHostChecker.checkerMu.Lock()
	GlobalHostChecker.checker.sampleTriggerLimit = 1
	GlobalHostChecker.checkerMu.Unlock()
	defer func() {
		apisMu.Lock()
		apisByID = make(map[string]*APISpec)
		apisMu.Unlock()
		GlobalHostChecker.checkerMu.Lock()
		GlobalHostChecker.checker.sampleTriggerLimit = defaultSampletTriggerLimit
		GlobalHostChecker.checkerMu.Unlock()
	}()

	SetCheckerHostList()

	hostCheckTicker <- struct{}{}
	eventWG.Wait()

	remote, _ := url.Parse(TestHttpAny)
	proxy := TykNewSingleHostReverseProxy(remote, spec)

	req := TestReq(t, "GET", "/", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)
	if rec.Code != 503 {
		t.Fatalf("wanted code to be 503, was %d", rec.Code)
	}
}

package main

import (
	"bytes"
	"sync"
	"testing"
	"text/template"

	"github.com/TykTechnologies/tyk/apidef"
)

const sampleUptimeTestAPI = `{
	"name": "API",
	"slug": "api",
	"api_id": "test",
	"use_keyless": true,
	"version_data": {
		"not_versioned": true,
		"versions": {
			"Default": {
				"name": "Default",
				"expires": "3000-01-02 15:04"
			}
		}
	},
	"uptime_tests": {
		"check_list": [
			{
				"url": "{{.ActiveHost}}/get",
				"method": "GET",
				"headers": {},
				"body": ""
			},
			{
				"url": "{{.InactiveHost}}/get",
				"method": "GET",
				"headers": {},
				"body": ""
			}
		]
	},
	"proxy": {
		"listen_path": "/",
		"enable_load_balancing": true,
		"check_host_against_uptime_tests": true,
		"target_list": [
			"{{.ActiveHost}}",
			"{{.InactiveHost}}"
		],
		"strip_listen_path": true
	},
	"active": true
}`

type testEventHandler struct {
	cb func(EventMessage)
}

func (w *testEventHandler) New(handlerConf interface{}) (TykEventHandler, error) {
	return w, nil
}

func (w *testEventHandler) HandleEvent(em EventMessage) {
	w.cb(em)
}

func TestHostChecker(t *testing.T) {
	specTmpl := template.Must(template.New("spec").Parse(sampleUptimeTestAPI))

	tmplData := struct {
		ActiveHost   string
		InactiveHost string
	}{
		testHttpAny,
		testHttpFailureAny,
	}

	specBuf := &bytes.Buffer{}
	specTmpl.ExecuteTemplate(specBuf, specTmpl.Name(), &tmplData)

	spec := createDefinitionFromString(specBuf.String())

	// From api_loader.go#processSpec
	sl := apidef.NewHostListFromList(spec.Proxy.Targets)
	spec.Proxy.StructuredTargetList = sl

	var wg sync.WaitGroup
	cb := func(em EventMessage) {
		wg.Done()
	}

	spec.EventPaths = map[apidef.TykEvent][]TykEventHandler{
		"HostDown": {&testEventHandler{cb}},
	}

	apisByID = map[string]*APISpec{spec.APIID: spec}
	GlobalHostChecker.checker.sampleTriggerLimit = 1
	defer func() {
		apisByID = make(map[string]*APISpec)
		GlobalHostChecker.checker.sampleTriggerLimit = defaultSampletTriggerLimit
	}()

	SetCheckerHostList()
	if len(GlobalHostChecker.currentHostList) != 2 {
		t.Error("Should update hosts manager check list", GlobalHostChecker.currentHostList)
	}

	if len(GlobalHostChecker.checker.newList) != 2 {
		t.Error("Should update host checker check list")
	}

	// Should receive one HostDown event
	wg.Add(1)
	for _, hostData := range GlobalHostChecker.checker.newList {
		// By default host check should fail > 3 times in row
		GlobalHostChecker.checker.CheckHost(hostData)
	}

	wg.Wait()

	if GlobalHostChecker.IsHostDown(testHttpAny) {
		t.Error("Should not mark as down")
	}

	if !GlobalHostChecker.IsHostDown(testHttpFailureAny) {
		t.Error("Should mark as down")
	}

	host1 := GetNextTarget(spec.Proxy.StructuredTargetList, spec, 0)
	host2 := GetNextTarget(spec.Proxy.StructuredTargetList, spec, 0)

	if host1 != host2 || host1 != testHttpAny {
		t.Error("Should return only active host", host1, host2)
	}

	if GlobalHostChecker.checker.checkTimeout != 10 {
		t.Error("Should set defaults", GlobalHostChecker.checker.checkTimeout)
	}

	if ttl, _ := GlobalHostChecker.store.GetKeyTTL(PoolerHostSentinelKeyPrefix + testHttpFailure); int(ttl) != GlobalHostChecker.checker.checkTimeout+1 {
		t.Error("HostDown expiration key should be checkTimeout + 1", ttl)
	}
}

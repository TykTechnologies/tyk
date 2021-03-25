package gateway

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"text/template"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/assert"

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
	proxy := TykNewSingleHostReverseProxy(remote, spec, nil)

	req := TestReq(t, "GET", "/", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)
	if rec.Code != 503 {
		t.Fatalf("wanted code to be 503, was %d", rec.Code)
	}
}

type answers struct {
	mu             sync.RWMutex
	ping, fail, up bool
	cancel         func()
}

func (a *answers) onFail(_ context.Context, _ HostHealthReport) {
	defer a.cancel()
	a.mu.Lock()
	a.fail = true
	a.mu.Unlock()
}

func (a *answers) onPing(_ context.Context, _ HostHealthReport) {
	defer a.cancel()
	a.mu.Lock()
	a.ping = true
	a.mu.Unlock()
}
func (a *answers) onUp(_ context.Context, _ HostHealthReport) {
	defer a.cancel()
	a.mu.Lock()
	a.up = true
	a.mu.Unlock()
}
func (a *answers) cb() HostCheckCallBacks {
	return HostCheckCallBacks{
		Up:   a.onUp,
		Ping: a.onPing,
		Fail: a.onFail,
	}
}

func TestTestCheckerTCPHosts_correct_answers(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	data := HostData{
		CheckURL: l.Addr().String(),
		Protocol: "tcp",
		Commands: []apidef.CheckCommand{
			{
				Name: "send", Message: "ping",
			}, {
				Name: "expect", Message: "pong",
			},
		},
	}
	go func(ls net.Listener) {
		for {
			s, err := ls.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 4)
			_, err = s.Read(buf)
			if err != nil {
				return
			}
			if string(buf) == "ping" {
				s.Write([]byte("pong"))
			} else {
				s.Write([]byte("unknown"))
			}
		}
	}(l)
	ctx, cancel := context.WithCancel(context.Background())
	hs := &HostUptimeChecker{}
	ans := &answers{cancel: cancel}
	setTestMode(false)

	hs.Init(1, 1, 1, map[string]HostData{
		l.Addr().String(): data,
	},
		ans.cb(),
	)
	hs.sampleTriggerLimit = 1
	go hs.Start(ctx)
	<-ctx.Done()
	hs.Stop()
	setTestMode(true)
	if !(ans.ping && !ans.fail && !ans.up) {
		t.Errorf("expected the host to be up : field:%v up:%v pinged:%v", ans.fail, ans.up, ans.ping)
	}
}
func TestTestCheckerTCPHosts_correct_answers_proxy_protocol(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	data := HostData{
		CheckURL:            l.Addr().String(),
		Protocol:            "tcp",
		EnableProxyProtocol: true,
		Commands: []apidef.CheckCommand{
			{
				Name: "send", Message: "ping",
			}, {
				Name: "expect", Message: "pong",
			},
		},
	}
	go func(ls net.Listener) {
		ls = &proxyproto.Listener{Listener: ls}
		for {
			s, err := ls.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 4)
			_, err = s.Read(buf)
			if err != nil {
				return
			}
			if string(buf) == "ping" {
				s.Write([]byte("pong"))
			} else {
				s.Write([]byte("unknown"))
			}
		}
	}(l)
	ctx, cancel := context.WithCancel(context.Background())
	hs := &HostUptimeChecker{}
	ans := &answers{cancel: cancel}
	setTestMode(false)

	hs.Init(1, 1, 1, map[string]HostData{
		l.Addr().String(): data,
	},
		ans.cb(),
	)
	hs.sampleTriggerLimit = 1
	go hs.Start(ctx)
	<-ctx.Done()
	setTestMode(true)
	if !(ans.ping && !ans.fail && !ans.up) {
		t.Errorf("expected the host to be up : field:%v up:%v pinged:%v", ans.fail, ans.up, ans.ping)
	}
}

func TestTestCheckerTCPHosts_correct_wrong_answers(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	data := HostData{
		CheckURL: l.Addr().String(),
		Protocol: "tcp",
		Commands: []apidef.CheckCommand{
			{
				Name: "send", Message: "ping",
			}, {
				Name: "expect", Message: "pong",
			},
		},
	}
	go func(ls net.Listener) {
		for {
			s, err := ls.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 4)
			_, err = s.Read(buf)
			if err != nil {
				return
			}
			s.Write([]byte("unknown"))
		}
	}(l)
	ctx, cancel := context.WithCancel(context.Background())
	hs := &HostUptimeChecker{}
	failed := false
	setTestMode(false)
	hs.Init(1, 1, 1, map[string]HostData{
		l.Addr().String(): data,
	},
		HostCheckCallBacks{
			Fail: func(_ context.Context, _ HostHealthReport) {
				failed = true
				cancel()
			},
		},
	)
	hs.sampleTriggerLimit = 1
	go hs.Start(ctx)
	<-ctx.Done()
	setTestMode(true)
	if !failed {
		t.Error("expected the host check to fai")
	}
}

func TestProxyWhenHostIsDown(t *testing.T) {
	g := config.Global()
	g.UptimeTests.Config.FailureTriggerSampleSize = 1
	g.UptimeTests.Config.TimeWait = 5
	g.UptimeTests.Config.EnableUptimeAnalytics = true
	config.SetGlobal(g)

	ts := StartTest()
	defer ts.Close()

	defer ResetTestConfig()
	l := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer l.Close()
	BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.EnableLoadBalancing = true
		spec.Proxy.Targets = []string{l.URL}
		spec.Proxy.CheckHostAgainstUptimeTests = true
		spec.UptimeTests.CheckList = []apidef.HostCheckObject{
			{CheckURL: l.URL},
		}
	})
	GlobalHostChecker.checkerMu.Lock()
	GlobalHostChecker.checker.sampleTriggerLimit = 1
	GlobalHostChecker.checkerMu.Unlock()

	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	x := 0
	get := func() {
		x++
		res, err := http.Get(ts.URL + "/")
		if err == nil {
			res.Body.Close()
		}
		code := http.StatusOK
		if x > 2 {
			code = http.StatusServiceUnavailable
		}
		if res.StatusCode != code {
			t.Errorf("%d: expected %d got %d", x, code, res.StatusCode)
		}
	}
	n := 0
	sentSignal := false
	for {
		select {
		case <-tick.C:
			if sentSignal {
				sentSignal = !sentSignal
				continue
			}
			if n == 2 {
				l.Close()
				hostCheckTicker <- struct{}{}
				n++
				sentSignal = true
				continue
			}
			n++
			if n == 10 {
				return
			}
			get()
		}
	}
}

func TestChecker_triggerSampleLimit(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Close()

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(5)

	setTestMode(false)
	defer func() {
		setTestMode(true)
	}()

	var (
		limit  = 4
		ping   atomic.Value
		failed atomic.Value
	)
	failed.Store(0)
	ping.Store(0)

	hs := &HostUptimeChecker{}
	hs.Init(1, limit, 1, map[string]HostData{
		l.Addr().String(): {CheckURL: "http://" + l.Addr().String()},
	},
		HostCheckCallBacks{
			Ping: func(_ context.Context, _ HostHealthReport) {
				ping.Store(ping.Load().(int) + 1)
				if ping.Load().(int) >= limit {
					cancel()
				}
				wg.Done()
			},
			Fail: func(_ context.Context, _ HostHealthReport) {
				failed.Store(failed.Load().(int) + 1)
				wg.Done()
			},
		},
	)
	go hs.Start(ctx)

	wg.Wait()
	assert.Equal(t, limit, ping.Load().(int), "ping count is wrong")
	assert.Equal(t, 1, failed.Load().(int), "expected host down to be fired once")
}

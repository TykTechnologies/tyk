package gateway

import (
	"bytes"
	"context"
	"fmt"
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
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/test"
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

//// ToDo check why it blocks
func TestHostChecker(t *testing.T) {
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.UptimeTests.PollerGroup = uuid.NewV4().String()
	})
	defer ts.Close()

	specTmpl := template.Must(template.New("spec").Parse(sampleUptimeTestAPI))

	tmplData := struct {
		Host1, Host2 string
	}{
		TestHttpAny,
		testHttpFailureAny,
	}

	specBuf := &bytes.Buffer{}
	specTmpl.ExecuteTemplate(specBuf, specTmpl.Name(), &tmplData)

	spec := ts.Gw.CreateDefinitionFromString(specBuf.String())

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

	ts.Gw.apisMu.Lock()
	ts.Gw.apisByID = map[string]*APISpec{spec.APIID: spec}
	ts.Gw.apisMu.Unlock()
	ts.Gw.GlobalHostChecker.checkerMu.Lock()

	if ts.Gw.GlobalHostChecker.checker == nil {
		t.Fatal("is nil")
	}
	ts.Gw.GlobalHostChecker.checker.sampleTriggerLimit = 1
	ts.Gw.GlobalHostChecker.checkerMu.Unlock()
	defer func() {
		ts.Gw.apisMu.Lock()
		ts.Gw.apisByID = make(map[string]*APISpec)
		ts.Gw.apisMu.Unlock()
		ts.Gw.GlobalHostChecker.checkerMu.Lock()
		ts.Gw.GlobalHostChecker.checker.sampleTriggerLimit = defaultSampletTriggerLimit
		ts.Gw.GlobalHostChecker.checkerMu.Unlock()
	}()

	ts.Gw.SetCheckerHostList()
	ts.Gw.GlobalHostChecker.checkerMu.Lock()
	if len(ts.Gw.GlobalHostChecker.currentHostList) != 2 {
		t.Error("Should update hosts manager check list", ts.Gw.GlobalHostChecker.currentHostList)
	}

	if len(ts.Gw.GlobalHostChecker.checker.newList) != 2 {
		t.Error("Should update host checker check list")
	}
	ts.Gw.GlobalHostChecker.checkerMu.Unlock()
	ts.Gw.HostCheckTicker <- struct{}{}
	eventWG.Wait()

	if ts.Gw.GlobalHostChecker.HostDown(TestHttpAny) {
		t.Error("Should not mark as down")
	}

	if !ts.Gw.GlobalHostChecker.HostDown(testHttpFailureAny) {
		t.Error("Should mark as down")
	}

	// Test it many times concurrently, to simulate concurrent and
	// parallel requests to the API. This will catch bugs in those
	// scenarios, like data races.
	var targetWG sync.WaitGroup
	for i := 0; i < 10; i++ {
		targetWG.Add(1)
		go func() {
			host, err := ts.Gw.nextTarget(spec.Proxy.StructuredTargetList, spec)
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

	ts.Gw.GlobalHostChecker.checkerMu.Lock()
	if ts.Gw.GlobalHostChecker.checker.checkTimeout != defaultTimeout {
		t.Error("Should set defaults", ts.Gw.GlobalHostChecker.checker.checkTimeout)
	}

	redisStore := ts.Gw.GlobalHostChecker.store.(*storage.RedisCluster)
	if ttl, _ := redisStore.GetKeyTTL(PoolerHostSentinelKeyPrefix + testHttpFailure); int(ttl) != ts.Gw.GlobalHostChecker.checker.checkTimeout*ts.Gw.GlobalHostChecker.checker.sampleTriggerLimit {
		t.Error("HostDown expiration key should be checkTimeout + 1", ttl)
	}
	ts.Gw.GlobalHostChecker.checkerMu.Unlock()
}

func TestReverseProxyAllDown(t *testing.T) {

	ts := StartTest(func(globalConf *config.Config) {
		globalConf.UptimeTests.PollerGroup = uuid.NewV4().String()
	})
	defer ts.Close()

	specTmpl := template.Must(template.New("spec").Parse(sampleUptimeTestAPI))

	tmplData := struct {
		Host1, Host2 string
	}{
		testHttpFailureAny,
		testHttpFailureAny,
	}

	specBuf := &bytes.Buffer{}
	specTmpl.ExecuteTemplate(specBuf, specTmpl.Name(), &tmplData)

	spec := ts.Gw.CreateDefinitionFromString(specBuf.String())

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
	ts.Gw.GlobalHostChecker.checkerMu.Lock()
	if ts.Gw.GlobalHostChecker.checker == nil {
		fmt.Printf("\nStop loop: %v\n", !ts.Gw.GlobalHostChecker.stopLoop)
		fmt.Printf("\n Am I pooling: %v\n", ts.Gw.GlobalHostChecker.AmIPolling())
	}
	ts.Gw.GlobalHostChecker.checkerMu.Unlock()

	ts.Gw.apisMu.Lock()
	ts.Gw.apisByID = map[string]*APISpec{spec.APIID: spec}
	ts.Gw.apisMu.Unlock()
	ts.Gw.GlobalHostChecker.checkerMu.Lock()
	ts.Gw.GlobalHostChecker.checker.sampleTriggerLimit = 1
	ts.Gw.GlobalHostChecker.checkerMu.Unlock()
	defer func() {
		ts.Gw.apisMu.Lock()
		ts.Gw.apisByID = make(map[string]*APISpec)
		ts.Gw.apisMu.Unlock()
		ts.Gw.GlobalHostChecker.checkerMu.Lock()
		ts.Gw.GlobalHostChecker.checker.sampleTriggerLimit = defaultSampletTriggerLimit
		ts.Gw.GlobalHostChecker.checkerMu.Unlock()
	}()

	ts.Gw.SetCheckerHostList()

	ts.Gw.HostCheckTicker <- struct{}{}
	eventWG.Wait()

	remote, _ := url.Parse(TestHttpAny)
	proxy := ts.Gw.TykNewSingleHostReverseProxy(remote, spec, nil)

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
	ts := StartTest(nil)
	defer ts.Close()

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
	hs := &HostUptimeChecker{Gw: ts.Gw}
	ans := &answers{cancel: cancel}
	ts.Gw.setTestMode(false)

	hs.Init(1, 1, 1, map[string]HostData{
		l.Addr().String(): data,
	},
		ans.cb(),
	)
	hs.sampleTriggerLimit = 1
	go hs.Start(ctx)
	<-ctx.Done()
	hs.Stop()
	ts.Gw.setTestMode(true)
	if !(ans.ping && !ans.fail && !ans.up) {
		t.Errorf("expected the host to be up : field:%v up:%v pinged:%v", ans.fail, ans.up, ans.ping)
	}
}
func TestTestCheckerTCPHosts_correct_answers_proxy_protocol(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

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
	hs := &HostUptimeChecker{Gw: ts.Gw}
	ans := &answers{cancel: cancel}
	ts.Gw.setTestMode(false)

	hs.Init(1, 1, 1, map[string]HostData{
		l.Addr().String(): data,
	},
		ans.cb(),
	)
	hs.sampleTriggerLimit = 1
	go hs.Start(ctx)
	<-ctx.Done()
	ts.Gw.setTestMode(true)
	if !(ans.ping && !ans.fail && !ans.up) {
		t.Errorf("expected the host to be up : field:%v up:%v pinged:%v", ans.fail, ans.up, ans.ping)
	}
}

func TestTestCheckerTCPHosts_correct_wrong_answers(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

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
	hs := &HostUptimeChecker{Gw: ts.Gw}
	failed := false
	ts.Gw.setTestMode(false)
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
	ts.Gw.setTestMode(true)
	if !failed {
		t.Error("expected the host check to fai")
	}
}

func TestProxyWhenHostIsDown(t *testing.T) {
	conf := func(conf *config.Config) {
		conf.UptimeTests.Config.FailureTriggerSampleSize = 1
		conf.UptimeTests.Config.TimeWait = 5
		conf.UptimeTests.Config.EnableUptimeAnalytics = true
		conf.UptimeTests.PollerGroup = uuid.NewV4().String()
	}
	ts := StartTest(conf)
	defer ts.Close()

	l := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer l.Close()
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.EnableLoadBalancing = true
		spec.Proxy.Targets = []string{l.URL}
		spec.Proxy.CheckHostAgainstUptimeTests = true
		spec.UptimeTests.CheckList = []apidef.HostCheckObject{
			{CheckURL: l.URL},
		}
	})
	ts.Gw.GlobalHostChecker.checkerMu.Lock()
	ts.Gw.GlobalHostChecker.checker.sampleTriggerLimit = 1
	ts.Gw.GlobalHostChecker.checkerMu.Unlock()

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
				ts.Gw.HostCheckTicker <- struct{}{}
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
	test.Flaky(t) // TODO: TT-5258

	ts := StartTest(nil)
	defer ts.Close()
	ts.Gw.setTestMode(false)
	defer ts.Gw.setTestMode(true)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Close()

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(5)

	//ts.Gw.setTestMode(false)

	var (
		limit  = 4
		ping   atomic.Value
		failed atomic.Value
	)
	failed.Store(0)
	ping.Store(0)

	hs := &HostUptimeChecker{Gw: ts.Gw}
	hs.Init(1, limit, 0, map[string]HostData{
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

func TestChecker_HostReporter_up_then_down(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()
	ts.Gw.setTestMode(false)
	defer ts.Gw.setTestMode(true)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
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
	defer l.Close()

	changeResponse := make(chan bool)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func(ls net.Listener, change chan bool) {
		ls = &proxyproto.Listener{Listener: ls}
		accept := false
		for {
			select {
			case <-change:
				accept = true
			default:
				s, err := ls.Accept()
				if err != nil {
					return
				}
				buf := make([]byte, 4)
				_, err = s.Read(buf)
				if err != nil {
					return
				}
				if !accept {
					s.Write([]byte("pong"))
				} else {
					s.Write([]byte("unknown"))
				}
			}

		}
	}(l, changeResponse)

	var (
		limit  = 2
		ping   atomic.Value
		failed atomic.Value
	)
	failed.Store(0)
	ping.Store(0)

	hs := &HostUptimeChecker{Gw: ts.Gw}
	hs.Init(1, limit, 1, map[string]HostData{
		l.Addr().String(): data,
	},
		HostCheckCallBacks{
			Fail: func(_ context.Context, _ HostHealthReport) {
				failed.Store(failed.Load().(int) + 1)
			},
			Up: func(_ context.Context, _ HostHealthReport) {
			},
			Ping: func(_ context.Context, _ HostHealthReport) {
				ping.Store(ping.Load().(int) + 1)
			},
		},
	)

	go hs.Start(ctx)
	defer hs.Stop()

	for {
		val := ping.Load()
		if val != nil && val == 1 {
			break
		}
	}

	changeResponse <- true
	for {
		val := failed.Load()
		if val != nil && val.(int) == 1 {
			break
		}
	}

	val, found := hs.samples.Load(data.CheckURL)
	assert.Equal(t, true, found, "the host url should be in samples")
	assert.Equal(t, 1, failed.Load().(int), "expected host down to be fired once")

	samples := val.(HostSample)
	assert.Equal(t, true, samples.reachedLimit, "the host failures should have reached the error limit")
	assert.Equal(t, 2, samples.count, "samples count should be 2")
}

func TestChecker_HostReporter_down_then_up(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()
	ts.Gw.setTestMode(false)
	defer ts.Gw.setTestMode(true)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
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
	defer l.Close()

	changeResponse := make(chan bool)

	go func(ls net.Listener, change chan bool) {
		ls = &proxyproto.Listener{Listener: ls}
		accept := false
		for {
			select {
			case <-change:
				accept = true
			default:
				s, err := ls.Accept()
				if err != nil {
					return
				}
				buf := make([]byte, 4)
				_, err = s.Read(buf)
				if err != nil {
					return
				}
				if accept {
					s.Write([]byte("pong"))
				} else {
					s.Write([]byte("unknown"))
				}
			}

		}
	}(l, changeResponse)

	var (
		limit  = 2
		up     atomic.Value
		failed atomic.Value
	)
	failed.Store(0)
	up.Store(0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hs := &HostUptimeChecker{Gw: ts.Gw}
	hs.Init(1, limit, 1, map[string]HostData{
		l.Addr().String(): data,
	}, HostCheckCallBacks{
		Fail: func(_ context.Context, _ HostHealthReport) {
			failed.Store(failed.Load().(int) + 1)
		},
		Up: func(_ context.Context, _ HostHealthReport) {
			up.Store(up.Load().(int) + 1)
		},
		Ping: func(_ context.Context, _ HostHealthReport) {
		},
	},
	)

	go hs.Start(ctx)
	defer hs.Stop()

	for {
		val := failed.Load()
		if val != nil && val.(int) == 1 {
			break
		}
	}

	changeResponse <- true

	for {
		val := up.Load()
		if val != nil && val == 1 {
			break
		}
	}

	_, found := hs.samples.Load(data.CheckURL)
	assert.Equal(t, false, found, "the host url should be in samples")
	assert.Equal(t, 2, failed.Load().(int), "expected host down to be fired twice")
	assert.Equal(t, 1, up.Load().(int), "expected host up to be fired once")

}

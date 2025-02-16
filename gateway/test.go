package gateway

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
)

type Test struct {
	URL        string
	testRunner *test.HTTPTestRunner
	// GlobalConfig deprecate this and instead use GW.getConfig()
	GlobalConfig     config.Config
	config           TestConfig
	Gw               *Gateway `json:"-"`
	HttpHandler      *http.Server
	TestServerRouter *mux.Router

	ctx    context.Context
	cancel context.CancelFunc

	dynamicHandlers map[string]http.HandlerFunc

	Parent testing.TB
}

type TestConfig struct {
	SeparateControlAPI bool
	Delay              time.Duration
	HotReload          bool
	overrideDefaults   bool
	CoprocessConfig    config.CoProcessConfig
}

type TestOption func(*Test)

func NewTest(tb testing.TB, genConf func(*config.Config), opts ...TestOption) *Test {
	tb.Helper()

	t := &Test{
		Parent:          tb,
		dynamicHandlers: make(map[string]http.HandlerFunc),
	}

	for _, optfn := range opts {
		optfn(t)
	}

	t.Gw = t.start(genConf)

	tb.Cleanup(t.Close)

	return t
}

func NewTestConfigOption(conf TestConfig) func(*Test) {
	return func(t *Test) {
		t.config = conf
	}
}

// Start is the root event point where a gateway object is created, and
// can enforce lifecycle via the *Test objects, and TestOption implementation.
// For example, if somebody wanted to have some default options set up,
// one could set a timeout by implementing:
//
// - `func NewTestTimeoutOption(d time.Duration) func(*Test)`
//
// To use, it should be passed to NewTest as an argument. A default timeout
// may be implemented in the future and set from NewTest as well.
func (s *Test) start(genConf func(globalConf *config.Config)) *Gateway {
	// init and create gw
	ctx, cancel := context.WithCancel(context.Background())

	log.Info("starting test")

	s.ctx = ctx
	s.cancel = func() {
		cancel()
		log.Info("Cancelling test context")
	}

	gw := s.newGateway(genConf)
	gw.setupPortsWhitelist()
	gw.startServer()
	gw.setupGlobals()

	// Set up a default org manager so we can traverse non-live paths
	if !gw.GetConfig().SupressDefaultOrgStore {
		gw.DefaultOrgStore.Init(gw.getGlobalStorageHandler("orgkey.", false))
		gw.DefaultQuotaStore.Init(gw.getGlobalStorageHandler("orgkey.", false))
	}

	s.GlobalConfig = gw.GetConfig()

	scheme := "http://"
	if s.GlobalConfig.HttpServerOptions.UseSSL {
		scheme = "https://"
	}

	s.URL = scheme + gw.DefaultProxyMux.getProxy(gw.GetConfig().ListenPort, gw.GetConfig()).listener.Addr().String()

	s.testRunner = &test.HTTPTestRunner{
		RequestBuilder: func(tc *test.TestCase) (*http.Request, error) {
			tc.BaseURL = s.URL
			if tc.ControlRequest {
				if s.config.SeparateControlAPI {
					tc.BaseURL = scheme + s.controlProxy().listener.Addr().String()
				} else if s.GlobalConfig.ControlAPIHostname != "" {
					tc.Domain = s.GlobalConfig.ControlAPIHostname
				}
			}
			r, err := test.NewRequest(tc)

			if tc.AdminAuth {
				r = s.withAuth(r)
			}

			if s.config.Delay > 0 {
				tc.Delay = s.config.Delay
			}

			return r, err
		},
		Do: test.HttpServerRunner(),
	}

	return gw
}

// Close is the shutdown lifecycle for a gateway integration test w/ storage.
func (s *Test) Close() {
	defer s.cancel()

	for _, p := range s.Gw.DefaultProxyMux.proxies {
		if p.listener != nil {
			p.listener.Close()
		}
	}

	gwConfig := s.Gw.GetConfig()

	s.Gw.DefaultProxyMux.swap(&proxyMux{}, s.Gw)
	if s.config.SeparateControlAPI {
		gwConfig.ControlAPIPort = 0
		s.Gw.SetConfig(gwConfig)
	}

	// if jsvm enabled we need to unmount to prevent high memory consumption
	if s.Gw.GetConfig().EnableJSVM {
		s.Gw.GlobalEventsJSVM.VM = nil
	}

	ctxShutDown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := s.HttpHandler.Shutdown(ctxShutDown)
	if err != nil {
		log.WithError(err).Error("shutting down the http handler")
	} else {
		log.Info("server exited properly")
	}

	s.Gw.Analytics.Stop()
	s.Gw.ReloadTestCase.StopTicker()
	s.Gw.GlobalHostChecker.StopPoller()
	s.Gw.NewRelicApplication.Shutdown(5 * time.Second)

	err = s.RemoveApis()
	if err != nil {
		log.WithError(err).Error("could not remove apis")
	}

	s.Gw.cacheClose()
}

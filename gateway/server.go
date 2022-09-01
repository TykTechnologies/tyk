package gateway

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/TykTechnologies/tyk/test"
	"html/template"
	"io/ioutil"
	stdlog "log"
	"log/syslog"
	"net"
	"net/http"
	pprof_http "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"

	"sync/atomic"
	textTemplate "text/template"
	"time"

	"github.com/TykTechnologies/again"
	"github.com/TykTechnologies/drl"
	gas "github.com/TykTechnologies/goautosocket"
	"github.com/TykTechnologies/gorpc"
	"github.com/TykTechnologies/goverify"
	"github.com/TykTechnologies/tyk-pump/serializer"
	logstashHook "github.com/bshuster-repo/logrus-logstash-hook"
	"github.com/evalphobia/logrus_sentry"
	graylogHook "github.com/gemnasium/logrus-graylog-hook"
	"github.com/gorilla/mux"
	"github.com/lonelycode/osin"
	newrelic "github.com/newrelic/go-agent"
	"github.com/pmylund/go-cache"
	"github.com/rs/cors"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	logrus_syslog "github.com/sirupsen/logrus/hooks/syslog"
	"rsc.io/letsencrypt"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/checkup"
	"github.com/TykTechnologies/tyk/cli"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/dnscache"
	"github.com/TykTechnologies/tyk/headers"
	logger "github.com/TykTechnologies/tyk/log"
	"github.com/TykTechnologies/tyk/regexp"
	"github.com/TykTechnologies/tyk/rpc"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/storage/kv"
	"github.com/TykTechnologies/tyk/trace"
	"github.com/TykTechnologies/tyk/user"
)

var (
	log       = logger.Get()
	mainLog   = log.WithField("prefix", "main")
	pubSubLog = log.WithField("prefix", "pub-sub")
	rawLog    = logger.GetRaw()

	memProfFile         *os.File
	NewRelicApplication newrelic.Application

	// confPaths is the series of paths to try to use as config files. The
	// first one to exist will be used. If none exists, a default config
	// will be written to the first path in the list.
	//
	// When --conf=foo is used, this will be replaced by []string{"foo"}.
	confPaths = []string{
		"tyk.conf",
		// TODO: add ~/.config/tyk/tyk.conf here?
		"/etc/tyk/tyk.conf",
	}
)

const appName = "tyk-gateway"

type Gateway struct {
	DefaultProxyMux *proxyMux
	config          atomic.Value
	configMu        sync.Mutex

	ctx context.Context

	muNodeID   sync.Mutex // guards NodeID
	NodeID     string
	drlOnce    sync.Once
	DRLManager *drl.DRL
	reloadMu   sync.Mutex

	Analytics            RedisAnalyticsHandler
	GlobalEventsJSVM     JSVM
	MainNotifier         RedisNotifier
	DefaultOrgStore      DefaultSessionManager
	DefaultQuotaStore    DefaultSessionManager
	GlobalSessionManager SessionHandler
	MonitoringHandler    config.TykEventHandler
	RPCListener          RPCStorageHandler
	DashService          DashboardServiceSender
	CertificateManager   *certs.CertificateManager
	GlobalHostChecker    HostCheckerManager
	HostCheckTicker      chan struct{}
	HostCheckerClient    *http.Client

	keyGen DefaultKeyGenerator

	SessionLimiter SessionLimiter
	SessionMonitor Monitor

	// RPCGlobalCache stores keys
	RPCGlobalCache *cache.Cache
	// RPCCertCache stores certificates
	RPCCertCache *cache.Cache
	// key session memory cache
	SessionCache *cache.Cache
	// org session memory cache
	ExpiryCache *cache.Cache
	// memory cache to store arbitrary items
	UtilCache *cache.Cache

	// Nonce to use when interacting with the dashboard service
	ServiceNonce      string
	ServiceNonceMutex sync.RWMutex

	apisMu          sync.RWMutex
	apiSpecs        []*APISpec
	apisByID        map[string]*APISpec
	apisHandlesByID *sync.Map

	policiesMu   sync.RWMutex
	policiesByID map[string]user.Policy

	dnsCacheManager dnscache.IDnsCacheManager

	consulKVStore kv.Store
	vaultKVStore  kv.Store

	LE_MANAGER  letsencrypt.Manager
	LE_FIRSTRUN bool

	NotificationVerifier goverify.Verifier

	RedisPurgeOnce sync.Once
	RpcPurgeOnce   sync.Once

	// OnConnect this is a callback which is called whenever we transition redis Disconnected to connected
	OnConnect func()

	// SessionID is the unique session id which is used while connecting to dashboard to prevent multiple node allocation.
	SessionID string

	runningTestsMu sync.RWMutex
	testMode       bool

	// reloadQueue is used by reloadURLStructure to queue a reload. It's not
	// buffered, as reloadQueueLoop should pick these up immediately.
	reloadQueue chan func()

	requeueLock sync.Mutex

	// This is a list of callbacks to execute on the next reload. It is protected by
	// requeueLock for concurrent use.
	requeue []func()

	// ReloadTestCase use this when in any test for gateway reloads
	ReloadTestCase *ReloadMachinery

	// map[bundleName]map[fileName]fileContent used for tests
	TestBundles  map[string]map[string]string
	TestBundleMu sync.Mutex

	templates    *template.Template
	templatesRaw *textTemplate.Template

	// RedisController keeps track of redis connection and singleton
	RedisController *storage.RedisController
	hostDetails     hostDetails

	healthCheckInfo atomic.Value

	dialCtxFn test.DialContext
}

type hostDetails struct {
	Hostname string
	PID      int
}

func NewGateway(config config.Config, ctx context.Context) *Gateway {
	gw := Gateway{
		DefaultProxyMux: &proxyMux{
			again: again.New(),
		},
		ctx: ctx,
	}

	gw.Analytics = RedisAnalyticsHandler{Gw: &gw}
	gw.SetConfig(config)
	sessionManager := DefaultSessionManager{Gw: &gw}
	gw.GlobalSessionManager = SessionHandler(&sessionManager)
	gw.DefaultOrgStore = DefaultSessionManager{Gw: &gw}
	gw.DefaultQuotaStore = DefaultSessionManager{Gw: &gw}
	gw.SessionLimiter = SessionLimiter{Gw: &gw}
	gw.SessionMonitor = Monitor{Gw: &gw}
	gw.HostCheckTicker = make(chan struct{})
	gw.HostCheckerClient = &http.Client{
		Timeout: 500 * time.Millisecond,
	}

	gw.SessionCache = cache.New(10*time.Second, 5*time.Second)
	gw.ExpiryCache = cache.New(600*time.Second, 10*time.Minute)
	gw.UtilCache = cache.New(time.Hour, 10*time.Minute)

	gw.apisByID = map[string]*APISpec{}
	gw.apisHandlesByID = new(sync.Map)

	gw.policiesByID = map[string]user.Policy{}

	// reload
	gw.reloadQueue = make(chan func())
	// only for tests
	gw.ReloadTestCase = NewReloadMachinery()
	gw.TestBundles = map[string]map[string]string{}

	gw.RedisController = storage.NewRedisController(ctx)

	return &gw
}

func (gw *Gateway) UnmarshalJSON(data []byte) error {
	return nil
}
func (gw *Gateway) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct{}{})
}

func (gw *Gateway) InitializeRPCCache() {
	conf := gw.GetConfig()
	gw.RPCGlobalCache = cache.New(time.Duration(conf.SlaveOptions.RPCGlobalCacheExpiration)*time.Second, 15*time.Second)
	gw.RPCCertCache = cache.New(time.Duration(conf.SlaveOptions.RPCCertCacheExpiration)*time.Second, 15*time.Second)
}

// SetNodeID writes NodeID safely.
func (gw *Gateway) SetNodeID(nodeID string) {
	gw.muNodeID.Lock()
	gw.NodeID = nodeID
	gw.muNodeID.Unlock()
}

// GetNodeID reads NodeID safely.
func (gw *Gateway) GetNodeID() string {
	gw.muNodeID.Lock()
	defer gw.muNodeID.Unlock()
	return gw.NodeID
}

func (gw *Gateway) isRunningTests() bool {
	gw.runningTestsMu.RLock()
	v := gw.testMode
	gw.runningTestsMu.RUnlock()
	return v
}

func (gw *Gateway) setTestMode(v bool) {
	gw.runningTestsMu.Lock()
	gw.testMode = v
	gw.runningTestsMu.Unlock()
}

func (gw *Gateway) getApiSpec(apiID string) *APISpec {
	gw.apisMu.RLock()
	spec := gw.apisByID[apiID]
	gw.apisMu.RUnlock()
	return spec
}

func (gw *Gateway) getPolicy(polID string) user.Policy {
	gw.policiesMu.RLock()
	pol := gw.policiesByID[polID]
	gw.policiesMu.RUnlock()
	return pol
}

func (gw *Gateway) apisByIDLen() int {
	gw.apisMu.RLock()
	defer gw.apisMu.RUnlock()
	return len(gw.apisByID)
}

// Create all globals and init connection handlers
func (gw *Gateway) setupGlobals() {
	gw.reloadMu.Lock()
	defer gw.reloadMu.Unlock()

	gwConfig := gw.GetConfig()
	checkup.Run(&gwConfig)

	gw.SetConfig(gwConfig)
	gw.dnsCacheManager = dnscache.NewDnsCacheManager(gwConfig.DnsCache.MultipleIPsHandleStrategy)

	if gwConfig.DnsCache.Enabled {
		gw.dnsCacheManager.InitDNSCaching(
			time.Duration(gwConfig.DnsCache.TTL)*time.Second,
			time.Duration(gwConfig.DnsCache.CheckInterval)*time.Second)
	}

	if gwConfig.EnableAnalytics && gwConfig.Storage.Type != "redis" {
		mainLog.Fatal("Analytics requires Redis Storage backend, please enable Redis in the tyk.conf file.")
	}

	// Initialise HostCheckerManager only if uptime tests are enabled.
	if !gwConfig.UptimeTests.Disable {
		if gwConfig.ManagementNode {
			mainLog.Warn("Running Uptime checks in a management node.")
		}

		healthCheckStore := storage.RedisCluster{KeyPrefix: "host-checker:", IsAnalytics: true, RedisController: gw.RedisController}
		gw.InitHostCheckManager(gw.ctx, &healthCheckStore)
	}

	gw.initHealthCheck(gw.ctx)

	redisStore := storage.RedisCluster{KeyPrefix: "apikey-", HashKeys: gwConfig.HashKeys, RedisController: gw.RedisController}
	gw.GlobalSessionManager.Init(&redisStore)

	versionStore := storage.RedisCluster{KeyPrefix: "version-check-", RedisController: gw.RedisController}
	versionStore.Connect()
	err := versionStore.SetKey("gateway", VERSION, 0)

	if err != nil {
		mainLog.WithError(err).Error("Could not set version in versionStore")
	}

	if gwConfig.EnableAnalytics && gw.Analytics.Store == nil {
		Conf := gwConfig
		Conf.LoadIgnoredIPs()
		gw.SetConfig(Conf)
		mainLog.Debug("Setting up analytics DB connection")

		analyticsStore := storage.RedisCluster{KeyPrefix: "analytics-", IsAnalytics: true, RedisController: gw.RedisController}
		gw.Analytics.Store = &analyticsStore
		gw.Analytics.Init()

		store := storage.RedisCluster{KeyPrefix: "analytics-", IsAnalytics: true, RedisController: gw.RedisController}
		redisPurger := RedisPurger{Store: &store, Gw: gw}
		go redisPurger.PurgeLoop(gw.ctx)

		if gw.GetConfig().AnalyticsConfig.Type == "rpc" {
			if gw.GetConfig().AnalyticsConfig.SerializerType == serializer.PROTOBUF_SERIALIZER {
				mainLog.Error("Protobuf analytics serialization is not supported with rpc analytics.")
			} else {
				mainLog.Debug("Using RPC cache purge")

				store := storage.RedisCluster{KeyPrefix: "analytics-", IsAnalytics: true, RedisController: gw.RedisController}
				purger := rpc.Purger{
					Store: &store,
				}
				purger.Connect()
				go purger.PurgeLoop(gw.ctx, time.Duration(gw.GetConfig().AnalyticsConfig.PurgeInterval))
			}

		}
		go gw.flushNetworkAnalytics(gw.ctx)
	}

	// Load all the files that have the "error" prefix.
	//	gwConfig.TemplatePath = "/Users/sredny/go/src/github.com/TykTechnologies/tyk/templates"
	templatesDir := filepath.Join(gwConfig.TemplatePath, "error*")
	gw.templates = template.Must(template.ParseGlob(templatesDir))
	gw.templatesRaw = textTemplate.Must(textTemplate.ParseGlob(templatesDir))
	gw.CoProcessInit()

	// Get the notifier ready
	mainLog.Debug("Notifier will not work in hybrid mode")
	mainNotifierStore := &storage.RedisCluster{RedisController: gw.RedisController}
	mainNotifierStore.Connect()
	gw.MainNotifier = RedisNotifier{mainNotifierStore, RedisPubSubChannel, gw}

	if gwConfig.Monitor.EnableTriggerMonitors {
		h := &WebHookHandler{Gw: gw}
		if err := h.Init(gwConfig.Monitor.Config); err != nil {
			mainLog.Error("Failed to initialise monitor! ", err)
		} else {
			gw.MonitoringHandler = h
		}
	}

	if conf := gw.GetConfig(); conf.AnalyticsConfig.NormaliseUrls.Enabled {
		mainLog.Info("Setting up analytics normaliser")
		conf.AnalyticsConfig.NormaliseUrls.CompiledPatternSet = gw.initNormalisationPatterns()
		gw.SetConfig(conf)
	}

	certificateSecret := gw.GetConfig().Secret
	if gw.GetConfig().Security.PrivateCertificateEncodingSecret != "" {
		certificateSecret = gw.GetConfig().Security.PrivateCertificateEncodingSecret
	}

	storeCert := &storage.RedisCluster{KeyPrefix: "cert-", HashKeys: false, RedisController: gw.RedisController}
	gw.CertificateManager = certs.NewCertificateManager(storeCert, certificateSecret, log, !gw.GetConfig().Cloud)
	if gw.GetConfig().SlaveOptions.UseRPC {
		rpcStore := &RPCStorageHandler{
			KeyPrefix: "cert-",
			HashKeys:  false,
			Gw:        gw,
		}
		gw.CertificateManager = certs.NewSlaveCertManager(storeCert, rpcStore, certificateSecret, log, !gw.GetConfig().Cloud)
	}

	if gw.GetConfig().NewRelic.AppName != "" {
		NewRelicApplication = gw.SetupNewRelic()
	}

	gw.readGraphqlPlaygroundTemplate()
}

func (gw *Gateway) buildDashboardConnStr(resource string) string {
	if gw.GetConfig().DBAppConfOptions.ConnectionString == "" && gw.GetConfig().DisableDashboardZeroConf {
		mainLog.Fatal("Connection string is empty, failing.")
	}

	if !gw.GetConfig().DisableDashboardZeroConf && gw.GetConfig().DBAppConfOptions.ConnectionString == "" {
		mainLog.Info("Waiting for zeroconf signal...")
		for gw.GetConfig().DBAppConfOptions.ConnectionString == "" {
			time.Sleep(1 * time.Second)
		}
	}

	return gw.GetConfig().DBAppConfOptions.ConnectionString + resource
}

func (gw *Gateway) syncAPISpecs() (int, error) {
	loader := APIDefinitionLoader{gw}

	var s []*APISpec
	if gw.GetConfig().UseDBAppConfigs {
		connStr := gw.buildDashboardConnStr("/system/apis")
		tmpSpecs, err := loader.FromDashboardService(connStr)
		if err != nil {
			log.Error("failed to load API specs: ", err)
			return 0, err
		}

		s = tmpSpecs

		mainLog.Debug("Downloading API Configurations from Dashboard Service")
	} else if gw.GetConfig().SlaveOptions.UseRPC {
		mainLog.Debug("Using RPC Configuration")

		var err error
		s, err = loader.FromRPC(gw.GetConfig().SlaveOptions.RPCKey, gw)
		if err != nil {
			return 0, err
		}
	} else {
		s = loader.FromDir(gw.GetConfig().AppPath)
	}

	mainLog.Printf("Detected %v APIs", len(s))

	if gw.GetConfig().AuthOverride.ForceAuthProvider {
		for i := range s {
			s[i].AuthProvider = gw.GetConfig().AuthOverride.AuthProvider
		}
	}

	if gw.GetConfig().AuthOverride.ForceSessionProvider {
		for i := range s {
			s[i].SessionProvider = gw.GetConfig().AuthOverride.SessionProvider
		}
	}
	var filter []*APISpec
	for _, v := range s {
		if err := v.Validate(); err != nil {
			mainLog.WithError(err).WithField("spec", v.Name).Error("Skipping loading spec because it failed validation")
			continue
		}
		filter = append(filter, v)
	}

	gw.apisMu.Lock()
	gw.apiSpecs = filter
	apiLen := len(gw.apiSpecs)
	tlsConfigCache.Flush()
	gw.apisMu.Unlock()

	return apiLen, nil
}

func (gw *Gateway) syncPolicies() (count int, err error) {
	var pols map[string]user.Policy

	mainLog.Info("Loading policies")

	switch gw.GetConfig().Policies.PolicySource {
	case "service":
		if gw.GetConfig().Policies.PolicyConnectionString == "" {
			mainLog.Fatal("No connection string or node ID present. Failing.")
		}
		connStr := gw.GetConfig().Policies.PolicyConnectionString
		connStr = connStr + "/system/policies"

		mainLog.Info("Using Policies from Dashboard Service")

		pols = gw.LoadPoliciesFromDashboard(connStr, gw.GetConfig().NodeSecret, gw.GetConfig().Policies.AllowExplicitPolicyID)
	case "rpc":
		mainLog.Debug("Using Policies from RPC")
		pols, err = gw.LoadPoliciesFromRPC(gw.GetConfig().SlaveOptions.RPCKey, gw.GetConfig().Policies.AllowExplicitPolicyID)
	default:
		//if policy path defined we want to allow use of the REST API
		if gw.GetConfig().Policies.PolicyPath != "" {
			pols = LoadPoliciesFromDir(gw.GetConfig().Policies.PolicyPath)

		} else if gw.GetConfig().Policies.PolicyRecordName == "" {
			// old way of doing things before REST Api added
			// this is the only case now where we need a policy record name
			mainLog.Debug("No policy record name defined, skipping...")
			return 0, nil
		} else {
			pols = LoadPoliciesFromFile(gw.GetConfig().Policies.PolicyRecordName)
		}
	}
	mainLog.Infof("Policies found (%d total):", len(pols))
	for id := range pols {
		mainLog.Debugf(" - %s", id)
	}

	gw.policiesMu.Lock()
	defer gw.policiesMu.Unlock()
	if len(pols) > 0 {
		gw.policiesByID = pols
	}

	return len(pols), err
}

// stripSlashes removes any trailing slashes from the request's URL
// path.
func stripSlashes(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if trim := strings.TrimRight(path, "/"); trim != path {
			r2 := *r
			r2.URL.Path = trim
			r = &r2
		}
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func (gw *Gateway) controlAPICheckClientCertificate(certLevel string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gw.GetConfig().Security.ControlAPIUseMutualTLS {
			if err := gw.CertificateManager.ValidateRequestCertificate(gw.GetConfig().Security.Certificates.ControlAPI, r); err != nil {
				doJSONWrite(w, http.StatusForbidden, apiError(err.Error()))
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// loadControlAPIEndpoints loads the endpoints used for controlling the Gateway.
func (gw *Gateway) loadControlAPIEndpoints(muxer *mux.Router) {
	hostname := gw.GetConfig().HostName
	if gw.GetConfig().ControlAPIHostname != "" {
		hostname = gw.GetConfig().ControlAPIHostname
	}

	if muxer == nil {
		cp := gw.GetConfig().ControlAPIPort
		muxer = gw.DefaultProxyMux.router(cp, "", gw.GetConfig())
		if muxer == nil {
			if cp != 0 {
				log.Error("Can't find control API router")
			}
			return
		}
	}

	muxer.HandleFunc("/"+gw.GetConfig().HealthCheckEndpointName, gw.liveCheckHandler)

	r := mux.NewRouter()
	muxer.PathPrefix("/tyk/").Handler(http.StripPrefix("/tyk",
		stripSlashes(gw.checkIsAPIOwner(gw.controlAPICheckClientCertificate("/gateway/client", InstrumentationMW(r)))),
	))

	if hostname != "" {
		muxer = muxer.Host(hostname).Subrouter()
		mainLog.Info("Control API hostname set: ", hostname)
	}

	if *cli.HTTPProfile || gw.GetConfig().HTTPProfile {
		muxer.HandleFunc("/debug/pprof/profile", pprof_http.Profile)
		muxer.HandleFunc("/debug/pprof/{_:.*}", pprof_http.Index)
	}

	r.MethodNotAllowedHandler = MethodNotAllowedHandler{}

	mainLog.Info("Initialising Tyk REST API Endpoints")

	// set up main API handlers
	r.HandleFunc("/reload/group", gw.groupResetHandler).Methods("GET")
	r.HandleFunc("/reload", gw.resetHandler(nil)).Methods("GET")

	if !gw.isRPCMode() {
		r.HandleFunc("/org/keys", gw.orgHandler).Methods("GET")
		r.HandleFunc("/org/keys/{keyName:[^/]*}", gw.orgHandler).Methods("POST", "PUT", "GET", "DELETE")
		r.HandleFunc("/keys/policy/{keyName}", gw.policyUpdateHandler).Methods("POST")
		r.HandleFunc("/keys/create", gw.createKeyHandler).Methods("POST")
		r.HandleFunc("/apis", gw.apiHandler).Methods(http.MethodGet)
		r.HandleFunc("/apis", gw.blockInDashboardMode(gw.apiHandler)).Methods(http.MethodPost)
		r.HandleFunc("/apis/oas", gw.apiOASGetHandler).Methods(http.MethodGet)
		r.HandleFunc("/apis/oas", gw.blockInDashboardMode(gw.validateOAS(gw.apiOASPostHandler))).Methods(http.MethodPost)
		r.HandleFunc("/apis/{apiID}", gw.apiHandler).Methods(http.MethodGet)
		r.HandleFunc("/apis/{apiID}", gw.blockInDashboardMode(gw.apiHandler)).Methods(http.MethodPost)
		r.HandleFunc("/apis/{apiID}", gw.blockInDashboardMode(gw.apiHandler)).Methods(http.MethodPut)
		r.HandleFunc("/apis/{apiID}", gw.apiHandler).Methods(http.MethodDelete)
		r.HandleFunc("/apis/oas/export", gw.apiOASExportHandler).Methods("GET")
		r.HandleFunc("/apis/oas/import", gw.blockInDashboardMode(gw.validateOAS(gw.makeImportedOASTykAPI(gw.apiOASPostHandler)))).Methods(http.MethodPost)
		r.HandleFunc("/apis/oas/{apiID}", gw.apiOASGetHandler).Methods(http.MethodGet)
		r.HandleFunc("/apis/oas/{apiID}", gw.blockInDashboardMode(gw.validateOAS(gw.apiOASPutHandler))).Methods(http.MethodPut)
		r.HandleFunc("/apis/oas/{apiID}", gw.blockInDashboardMode(gw.validateOAS(gw.apiOASPatchHandler))).Methods(http.MethodPatch)
		r.HandleFunc("/apis/oas/{apiID}", gw.blockInDashboardMode(gw.apiHandler)).Methods(http.MethodDelete)
		r.HandleFunc("/apis/oas/{apiID}/export", gw.apiOASExportHandler).Methods("GET")
		r.HandleFunc("/health", gw.healthCheckhandler).Methods("GET")
		r.HandleFunc("/policies", gw.polHandler).Methods("GET", "POST", "PUT", "DELETE")
		r.HandleFunc("/policies/{polID}", gw.polHandler).Methods("GET", "POST", "PUT", "DELETE")
		r.HandleFunc("/oauth/clients/create", gw.createOauthClient).Methods("POST")
		r.HandleFunc("/oauth/clients/{apiID}/{keyName:[^/]*}", gw.oAuthClientHandler).Methods("PUT")
		r.HandleFunc("/oauth/clients/{apiID}/{keyName:[^/]*}/rotate", gw.rotateOauthClientHandler).Methods("PUT")
		r.HandleFunc("/oauth/clients/apis/{appID}", gw.getApisForOauthApp).Queries("orgID", "{[0-9]*?}").Methods("GET")
		r.HandleFunc("/oauth/refresh/{keyName}", gw.invalidateOauthRefresh).Methods("DELETE")
		r.HandleFunc("/oauth/revoke", gw.RevokeTokenHandler).Methods("POST")
		r.HandleFunc("/oauth/revoke_all", gw.RevokeAllTokensHandler).Methods("POST")

	} else {
		mainLog.Info("Node is slaved, REST API minimised")
	}

	r.HandleFunc("/debug", gw.traceHandler).Methods("POST")
	r.HandleFunc("/cache/{apiID}", gw.invalidateCacheHandler).Methods("DELETE")
	r.HandleFunc("/keys", gw.keyHandler).Methods("POST", "PUT", "GET", "DELETE")
	r.HandleFunc("/keys/preview", gw.previewKeyHandler).Methods("POST")
	r.HandleFunc("/keys/{keyName:[^/]*}", gw.keyHandler).Methods("POST", "PUT", "GET", "DELETE")
	r.HandleFunc("/certs", gw.certHandler).Methods("POST", "GET")
	r.HandleFunc("/certs/{certID:[^/]*}", gw.certHandler).Methods("POST", "GET", "DELETE")
	r.HandleFunc("/oauth/clients/{apiID}", gw.oAuthClientHandler).Methods("GET", "DELETE")
	r.HandleFunc("/oauth/clients/{apiID}/{keyName:[^/]*}", gw.oAuthClientHandler).Methods("GET", "DELETE")
	r.HandleFunc("/oauth/clients/{apiID}/{keyName}/tokens", gw.oAuthClientTokensHandler).Methods("GET")

	r.HandleFunc("/schema", gw.schemaHandler).Methods(http.MethodGet)

	mainLog.Debug("Loaded API Endpoints")
}

// checkIsAPIOwner will ensure that the accessor of the tyk API has the
// correct security credentials - this is a shared secret between the
// client and the owner and is set in the tyk.conf file. This should
// never be made public!
func (gw *Gateway) checkIsAPIOwner(next http.Handler) http.Handler {
	secret := gw.GetConfig().Secret
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tykAuthKey := r.Header.Get(headers.XTykAuthorization)
		if tykAuthKey != secret {
			// Error
			mainLog.Warning("Attempted administrative access with invalid or missing key!")

			doJSONWrite(w, http.StatusForbidden, apiError("Attempted administrative access with invalid or missing key!"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func generateOAuthPrefix(apiID string) string {
	return "oauth-data." + apiID + "."
}

// Create API-specific OAuth handlers and respective auth servers
func (gw *Gateway) addOAuthHandlers(spec *APISpec, muxer *mux.Router) *OAuthManager {

	apiAuthorizePath := "/tyk/oauth/authorize-client{_:/?}"
	clientAuthPath := "/oauth/authorize{_:/?}"
	clientAccessPath := "/oauth/token{_:/?}"
	revokeToken := "/oauth/revoke"
	revokeAllTokens := "/oauth/revoke_all"

	serverConfig := osin.NewServerConfig()

	gwConfig := gw.GetConfig()
	if gwConfig.OauthErrorStatusCode != 0 {
		serverConfig.ErrorStatusCode = gwConfig.OauthErrorStatusCode
	} else {
		serverConfig.ErrorStatusCode = http.StatusForbidden
	}

	serverConfig.AllowedAccessTypes = spec.Oauth2Meta.AllowedAccessTypes
	serverConfig.AllowedAuthorizeTypes = spec.Oauth2Meta.AllowedAuthorizeTypes
	serverConfig.RedirectUriSeparator = gwConfig.OauthRedirectUriSeparator

	prefix := generateOAuthPrefix(spec.APIID)
	storageManager := gw.getGlobalMDCBStorageHandler(prefix, false)
	storageManager.Connect()
	osinStorage := &RedisOsinStorageInterface{
		storageManager,
		gw.GlobalSessionManager,
		&storage.RedisCluster{KeyPrefix: prefix, HashKeys: false, RedisController: gw.RedisController},
		spec.OrgID,
		gw,
	}

	osinServer := gw.TykOsinNewServer(serverConfig, osinStorage)

	oauthManager := OAuthManager{spec, osinServer, gw}
	oauthHandlers := OAuthHandlers{oauthManager}

	muxer.Handle(apiAuthorizePath, gw.checkIsAPIOwner(allowMethods(oauthHandlers.HandleGenerateAuthCodeData, "POST")))
	muxer.HandleFunc(clientAuthPath, allowMethods(oauthHandlers.HandleAuthorizePassthrough, "GET", "POST"))
	muxer.HandleFunc(clientAccessPath, addSecureAndCacheHeaders(allowMethods(oauthHandlers.HandleAccessRequest, "GET", "POST")))
	muxer.HandleFunc(revokeToken, oauthHandlers.HandleRevokeToken)
	muxer.HandleFunc(revokeAllTokens, oauthHandlers.HandleRevokeAllTokens)
	return &oauthManager
}

func (gw *Gateway) addBatchEndpoint(spec *APISpec, subrouter *mux.Router) {
	mainLog.Debug("Batch requests enabled for API")
	batchHandler := BatchRequestHandler{API: spec, Gw: gw}
	subrouter.HandleFunc("/tyk/batch/", batchHandler.HandleBatchRequest)
}

func (gw *Gateway) loadCustomMiddleware(spec *APISpec) ([]string, apidef.MiddlewareDefinition, []apidef.MiddlewareDefinition, []apidef.MiddlewareDefinition, []apidef.MiddlewareDefinition, []apidef.MiddlewareDefinition, apidef.MiddlewareDriver) {
	mwPaths := []string{}
	var mwAuthCheckFunc apidef.MiddlewareDefinition
	mwPreFuncs := []apidef.MiddlewareDefinition{}
	mwPostFuncs := []apidef.MiddlewareDefinition{}
	mwPostKeyAuthFuncs := []apidef.MiddlewareDefinition{}
	mwResponseFuncs := []apidef.MiddlewareDefinition{}
	mwDriver := apidef.OttoDriver

	// Set AuthCheck hook
	if spec.CustomMiddleware.AuthCheck.Name != "" {
		mwAuthCheckFunc = spec.CustomMiddleware.AuthCheck
		if spec.CustomMiddleware.AuthCheck.Path != "" {
			// Feed a JS file to Otto
			mwPaths = append(mwPaths, spec.CustomMiddleware.AuthCheck.Path)
		}
	}

	// Load from the configuration
	for _, mwObj := range spec.CustomMiddleware.Pre {
		mwPaths = append(mwPaths, mwObj.Path)
		mwPreFuncs = append(mwPreFuncs, mwObj)
		mainLog.Debug("Loading custom PRE-PROCESSOR middleware: ", mwObj.Name)
	}
	for _, mwObj := range spec.CustomMiddleware.Post {
		mwPaths = append(mwPaths, mwObj.Path)
		mwPostFuncs = append(mwPostFuncs, mwObj)
		mainLog.Debug("Loading custom POST-PROCESSOR middleware: ", mwObj.Name)
	}

	// Load from folders
	for _, folder := range [...]struct {
		name   string
		single *apidef.MiddlewareDefinition
		slice  *[]apidef.MiddlewareDefinition
	}{
		{name: "pre", slice: &mwPreFuncs},
		{name: "auth", single: &mwAuthCheckFunc},
		{name: "post_auth", slice: &mwPostKeyAuthFuncs},
		{name: "post", slice: &mwPostFuncs},
	} {
		globPath := filepath.Join(gw.GetConfig().MiddlewarePath, spec.APIID, folder.name, "*.js")
		paths, _ := filepath.Glob(globPath)
		for _, path := range paths {
			mainLog.Debug("Loading file middleware from ", path)

			mwDef := apidef.MiddlewareDefinition{
				Name: strings.Split(filepath.Base(path), ".")[0],
				Path: path,
			}
			mainLog.Debug("-- Middleware name ", mwDef.Name)
			mwDef.RequireSession = strings.HasSuffix(mwDef.Name, "_with_session")
			if mwDef.RequireSession {
				switch folder.name {
				case "post_auth", "post":
					mainLog.Debug("-- Middleware requires session")
				default:
					mainLog.Warning("Middleware requires session, but isn't post-auth: ", mwDef.Name)
				}
			}
			mwPaths = append(mwPaths, path)
			if folder.single != nil {
				*folder.single = mwDef
			} else {
				*folder.slice = append(*folder.slice, mwDef)
			}
		}
	}

	// Set middleware driver, defaults to OttoDriver
	if spec.CustomMiddleware.Driver != "" {
		mwDriver = spec.CustomMiddleware.Driver
	}

	// Load PostAuthCheck hooks
	for _, mwObj := range spec.CustomMiddleware.PostKeyAuth {
		if mwObj.Path != "" {
			// Otto files are specified here
			mwPaths = append(mwPaths, mwObj.Path)
		}
		mwPostKeyAuthFuncs = append(mwPostKeyAuthFuncs, mwObj)
	}

	// Load response hooks
	for _, mw := range spec.CustomMiddleware.Response {
		mwResponseFuncs = append(mwResponseFuncs, mw)
	}

	return mwPaths, mwAuthCheckFunc, mwPreFuncs, mwPostFuncs, mwPostKeyAuthFuncs, mwResponseFuncs, mwDriver

}

func (gw *Gateway) createResponseMiddlewareChain(spec *APISpec, responseFuncs []apidef.MiddlewareDefinition) {
	// Create the response processors

	responseChain := make([]TykResponseHandler, len(spec.ResponseProcessors))
	for i, processorDetail := range spec.ResponseProcessors {
		processor := gw.responseProcessorByName(processorDetail.Name)
		if processor == nil {
			mainLog.Error("No such processor: ", processorDetail.Name)
			return
		}
		if err := processor.Init(processorDetail.Options, spec); err != nil {
			mainLog.Debug("Failed to init processor: ", err)
		}
		mainLog.Debug("Loading Response processor: ", processorDetail.Name)
		responseChain[i] = processor
	}

	for _, mw := range responseFuncs {
		var processor TykResponseHandler
		//is it goplugin or other middleware
		if strings.HasSuffix(mw.Path, ".so") {
			processor = gw.responseProcessorByName("goplugin_res_hook")
		} else {
			processor = gw.responseProcessorByName("custom_mw_res_hook")
		}

		// TODO: perhaps error when plugin support is disabled?
		if processor == nil {
			mainLog.Error("Couldn't find custom middleware processor")
			return
		}

		if err := processor.Init(mw, spec); err != nil {
			mainLog.Debug("Failed to init processor: ", err)
		}
		responseChain = append(responseChain, processor)
	}

	spec.ResponseChain = responseChain
}

func handleCORS(router *mux.Router, spec *APISpec) {

	if spec.CORS.Enable {
		mainLog.Debug("CORS ENABLED")
		c := cors.New(cors.Options{
			AllowedOrigins:     spec.CORS.AllowedOrigins,
			AllowedMethods:     spec.CORS.AllowedMethods,
			AllowedHeaders:     spec.CORS.AllowedHeaders,
			ExposedHeaders:     spec.CORS.ExposedHeaders,
			AllowCredentials:   spec.CORS.AllowCredentials,
			MaxAge:             spec.CORS.MaxAge,
			OptionsPassthrough: spec.CORS.OptionsPassthrough,
			Debug:              spec.CORS.Debug,
		})

		router.Use(c.Handler)
	}
}

func (gw *Gateway) isRPCMode() bool {
	return gw.GetConfig().AuthOverride.ForceAuthProvider &&
		gw.GetConfig().AuthOverride.AuthProvider.StorageEngine == RPCStorageEngine
}

func (gw *Gateway) rpcReloadLoop(rpcKey string) {
	for {
		if ok := gw.RPCListener.CheckForReload(rpcKey); !ok {
			return
		}
	}
}

func (gw *Gateway) DoReload() {
	gw.reloadMu.Lock()
	defer gw.reloadMu.Unlock()

	// Initialize/reset the JSVM
	if gw.GetConfig().EnableJSVM {
		gw.GlobalEventsJSVM.Init(nil, logrus.NewEntry(log), gw)
	}

	// Load the API Policies
	if _, err := gw.syncPolicies(); err != nil {
		mainLog.Error("Error during syncing policies:", err.Error())
		return
	}

	// load the specs
	if count, err := gw.syncAPISpecs(); err != nil {
		mainLog.Error("Error during syncing apis:", err.Error())
		return
	} else {
		// skip re-loading only if dashboard service reported 0 APIs
		// and current registry had 0 APIs
		if count == 0 && gw.apisByIDLen() == 0 {
			mainLog.Warning("No API Definitions found, not reloading")
			return
		}
	}
	gw.loadGlobalApps()

	mainLog.Info("API reload complete")
}

// shouldReload returns true if we should perform any reload. Reloads happens if
// we have reload callback queued.
func (gw *Gateway) shouldReload() ([]func(), bool) {
	gw.requeueLock.Lock()
	defer gw.requeueLock.Unlock()
	if len(gw.requeue) == 0 {
		return nil, false
	}
	n := gw.requeue
	gw.requeue = []func(){}
	return n, true
}

func (gw *Gateway) reloadLoop(tick <-chan time.Time, complete ...func()) {
	for {
		select {
		case <-gw.ctx.Done():
			return
		// We don't check for reload right away as the gateway peroms this on the
		// startup sequence. We expect to start checking on the first tick after the
		// gateway is up and running.
		case <-tick:
			cb, ok := gw.shouldReload()
			if !ok {
				continue
			}
			start := time.Now()
			mainLog.Info("reload: initiating")
			gw.DoReload()
			mainLog.Info("reload: complete")
			mainLog.Info("Initiating coprocess reload")
			DoCoprocessReload()
			mainLog.Info("coprocess reload complete")
			for _, c := range cb {
				// most of the callbacks are nil, we don't want to execute nil functions to
				// avoid panics.
				if c != nil {
					c()
				}
			}
			if len(complete) != 0 {
				complete[0]()
			}
			mainLog.Infof("reload: cycle completed in %v", time.Since(start))
		}
	}
}

func (gw *Gateway) reloadQueueLoop(cb ...func()) {
	for {
		select {
		case <-gw.ctx.Done():
			log.Warn("Canceled ctx in reloadQueueLoop")
			return
		case fn := <-gw.reloadQueue:
			gw.requeueLock.Lock()
			gw.requeue = append(gw.requeue, fn)
			gw.requeueLock.Unlock()
			mainLog.Info("Reload queued")
			if len(cb) != 0 {
				cb[0]()
			}
		}
	}
}

// reloadURLStructure will queue an API reload. The reload will
// eventually create a new muxer, reload all the app configs for an
// instance and then replace the DefaultServeMux with the new one. This
// enables a reconfiguration to take place without stopping any requests
// from being handled.
//
// done will be called when the reload is finished. Note that if a
// reload is already queued, another won't be queued, but done will
// still be called when said queued reload is finished.
func (gw *Gateway) reloadURLStructure(done func()) {
	gw.reloadQueue <- done
}

func (gw *Gateway) setupLogger() {
	gwConfig := gw.GetConfig()
	if gwConfig.UseSentry {
		mainLog.Debug("Enabling Sentry support")

		logLevel := []logrus.Level{}

		if gwConfig.SentryLogLevel == "" {
			logLevel = []logrus.Level{
				logrus.PanicLevel,
				logrus.FatalLevel,
				logrus.ErrorLevel,
			}
		} else if gwConfig.SentryLogLevel == "panic" {
			logLevel = []logrus.Level{
				logrus.PanicLevel,
				logrus.FatalLevel,
			}
		}

		hook, err := logrus_sentry.NewSentryHook(gwConfig.SentryCode, logLevel)

		hook.Timeout = 0

		if err == nil {
			log.Hooks.Add(hook)
			rawLog.Hooks.Add(hook)
		}
		mainLog.Debug("Sentry hook active")
	}

	if gwConfig.UseSyslog {
		mainLog.Debug("Enabling Syslog support")
		hook, err := logrus_syslog.NewSyslogHook(gwConfig.SyslogTransport,
			gwConfig.SyslogNetworkAddr,
			syslog.LOG_INFO, "")

		if err == nil {
			log.Hooks.Add(hook)
			rawLog.Hooks.Add(hook)
		}
		mainLog.Debug("Syslog hook active")
	}

	if gwConfig.UseGraylog {
		mainLog.Debug("Enabling Graylog support")
		hook := graylogHook.NewGraylogHook(gwConfig.GraylogNetworkAddr,
			map[string]interface{}{"tyk-module": "gateway"})

		log.Hooks.Add(hook)
		rawLog.Hooks.Add(hook)

		mainLog.Debug("Graylog hook active")
	}

	if gwConfig.UseLogstash {
		mainLog.Debug("Enabling Logstash support")

		var hook *logstashHook.Hook
		var err error
		var conn net.Conn
		if gwConfig.LogstashTransport == "udp" {
			mainLog.Debug("Connecting to Logstash with udp")
			hook, err = logstashHook.NewHook(gwConfig.LogstashTransport,
				gwConfig.LogstashNetworkAddr,
				appName)
		} else {
			mainLog.Debugf("Connecting to Logstash with %s", gwConfig.LogstashTransport)
			conn, err = gas.Dial(gwConfig.LogstashTransport, gwConfig.LogstashNetworkAddr)
			if err == nil {
				hook, err = logstashHook.NewHookWithConn(conn, appName)
			}
		}

		if err != nil {
			log.Errorf("Error making connection for logstash: %v", err)
		} else {
			log.Hooks.Add(hook)
			rawLog.Hooks.Add(hook)
			mainLog.Debug("Logstash hook active")
		}
	}

	if gwConfig.UseRedisLog {
		hook := gw.newRedisHook()
		log.Hooks.Add(hook)
		rawLog.Hooks.Add(hook)

		mainLog.Debug("Redis log hook active")
	}
}

func (gw *Gateway) initialiseSystem() error {
	if gw.isRunningTests() && os.Getenv("TYK_LOGLEVEL") == "" {
		// `go test` without TYK_LOGLEVEL set defaults to no log
		// output
		log.SetLevel(logrus.ErrorLevel)
		log.SetOutput(ioutil.Discard)
		gorpc.SetErrorLogger(func(string, ...interface{}) {})
		stdlog.SetOutput(ioutil.Discard)
	} else if *cli.DebugMode {
		log.Level = logrus.DebugLevel
		mainLog.Debug("Enabling debug-level output")
	}

	if *cli.Conf != "" {
		mainLog.Debugf("Using %s for configuration", *cli.Conf)
		confPaths = []string{*cli.Conf}
	} else {
		mainLog.Debug("No configuration file defined, will try to use default (tyk.conf)")
	}

	mainLog.Infof("Tyk API Gateway %s", VERSION)

	if !gw.isRunningTests() {
		gwConfig := config.Config{}
		if err := config.Load(confPaths, &gwConfig); err != nil {
			return err
		}

		if gwConfig.PIDFileLocation == "" {
			gwConfig.PIDFileLocation = "/var/run/tyk/tyk-gateway.pid"
		}
		gw.SetConfig(gwConfig)
		gw.afterConfSetup()
	}

	overrideTykErrors(gw)

	gwConfig := gw.GetConfig()
	if os.Getenv("TYK_LOGLEVEL") == "" && !*cli.DebugMode {
		level := strings.ToLower(gwConfig.LogLevel)
		switch level {
		case "", "info":
			// default, do nothing
		case "error":
			log.Level = logrus.ErrorLevel
		case "warn":
			log.Level = logrus.WarnLevel
		case "debug":
			log.Level = logrus.DebugLevel
		default:
			mainLog.Fatalf("Invalid log level %q specified in config, must be error, warn, debug or info. ", level)
		}
	}

	if gwConfig.Storage.Type != "redis" {
		mainLog.Fatal("Redis connection details not set, please ensure that the storage type is set to Redis and that the connection parameters are correct.")
	}

	// suply rpc client globals to join it main loging and instrumentation sub systems
	rpc.Log = log
	rpc.Instrument = instrument

	gw.setupGlobals()
	gwConfig = gw.GetConfig()
	if *cli.Port != "" {
		portNum, err := strconv.Atoi(*cli.Port)
		if err != nil {
			mainLog.Error("Port specified in flags must be a number: ", err)
		} else {
			gwConfig.ListenPort = portNum
			gw.SetConfig(gwConfig)
		}
	}

	// Enable all the loggers
	gw.setupLogger()
	mainLog.Info("PIDFile location set to: ", gwConfig.PIDFileLocation)

	if err := writePIDFile(gw.GetConfig().PIDFileLocation); err != nil {
		mainLog.Error("Failed to write PIDFile: ", err)
	}

	if gw.GetConfig().UseDBAppConfigs && gw.GetConfig().Policies.PolicySource != config.DefaultDashPolicySource {
		gwConfig.Policies.PolicySource = config.DefaultDashPolicySource
		gwConfig.Policies.PolicyConnectionString = gwConfig.DBAppConfOptions.ConnectionString
		if gw.GetConfig().Policies.PolicyRecordName == "" {
			gwConfig.Policies.PolicyRecordName = config.DefaultDashPolicyRecordName
		}
	}

	if gwConfig.ProxySSLMaxVersion == 0 {
		gwConfig.ProxySSLMaxVersion = tls.VersionTLS12
	}

	if gwConfig.ProxySSLMinVersion > gwConfig.ProxySSLMaxVersion {
		gwConfig.ProxySSLMaxVersion = gwConfig.ProxySSLMinVersion
	}

	if gwConfig.HttpServerOptions.MaxVersion == 0 {
		gwConfig.HttpServerOptions.MaxVersion = tls.VersionTLS12
	}

	if gwConfig.HttpServerOptions.MinVersion > gwConfig.HttpServerOptions.MaxVersion {
		gwConfig.HttpServerOptions.MaxVersion = gwConfig.HttpServerOptions.MinVersion
	}

	if gwConfig.UseDBAppConfigs && gwConfig.Policies.PolicySource != config.DefaultDashPolicySource {
		gwConfig.Policies.PolicySource = config.DefaultDashPolicySource
		gwConfig.Policies.PolicyConnectionString = gwConfig.DBAppConfOptions.ConnectionString
		if gwConfig.Policies.PolicyRecordName == "" {
			gwConfig.Policies.PolicyRecordName = config.DefaultDashPolicyRecordName
		}
	}

	gw.SetConfig(gwConfig)
	config.Global = gw.GetConfig
	gw.getHostDetails(gw.GetConfig().PIDFileLocation)
	gw.InitializeRPCCache()
	gw.setupInstrumentation()

	if gw.GetConfig().HttpServerOptions.UseLE_SSL {
		go gw.StartPeriodicStateBackup(&gw.LE_MANAGER)
	}

	// cleanIdleMemConnProviders checks memconn.Provider (a part of internal API handling)
	// instances periodically and deletes idle items, closes net.Listener instances to
	// free resources.
	go cleanIdleMemConnProviders(gw.ctx)
	return nil
}

func writePIDFile(file string) error {
	if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
		return err
	}
	pid := strconv.Itoa(os.Getpid())
	return ioutil.WriteFile(file, []byte(pid), 0600)
}

func readPIDFromFile(file string) (int, error) {
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(string(b))
}

// afterConfSetup takes care of non-sensical config values (such as zero
// timeouts) and sets up a few globals that depend on the config.
func (gw *Gateway) afterConfSetup() {
	conf := gw.GetConfig()
	if conf.SlaveOptions.CallTimeout == 0 {
		conf.SlaveOptions.CallTimeout = 30
	}

	if conf.SlaveOptions.PingTimeout == 0 {
		conf.SlaveOptions.PingTimeout = 60
	}

	if conf.SlaveOptions.KeySpaceSyncInterval == 0 {
		conf.SlaveOptions.KeySpaceSyncInterval = 10
	}

	if conf.SlaveOptions.RPCCertCacheExpiration == 0 {
		// defaults to 1 hr
		conf.SlaveOptions.RPCCertCacheExpiration = 3600
	}

	if conf.SlaveOptions.RPCGlobalCacheExpiration == 0 {
		conf.SlaveOptions.RPCGlobalCacheExpiration = 30
	}

	if conf.AnalyticsConfig.PurgeInterval == 0 {
		// as default 10 seconds
		conf.AnalyticsConfig.PurgeInterval = 10
	}

	rpc.GlobalRPCPingTimeout = time.Second * time.Duration(conf.SlaveOptions.PingTimeout)
	rpc.GlobalRPCCallTimeout = time.Second * time.Duration(conf.SlaveOptions.CallTimeout)
	gw.initGenericEventHandlers()
	regexp.ResetCache(time.Second*time.Duration(conf.RegexpCacheExpire), !conf.DisableRegexpCache)

	if conf.HealthCheckEndpointName == "" {
		conf.HealthCheckEndpointName = "hello"
	}

	var err error

	conf.Secret, err = gw.kvStore(conf.Secret)
	if err != nil {
		log.Fatalf("could not retrieve the secret key.. %v", err)
	}

	conf.NodeSecret, err = gw.kvStore(conf.NodeSecret)
	if err != nil {
		log.Fatalf("could not retrieve the NodeSecret key.. %v", err)
	}

	conf.Storage.Password, err = gw.kvStore(conf.Storage.Password)
	if err != nil {
		log.Fatalf("Could not retrieve redis password... %v", err)
	}

	conf.CacheStorage.Password, err = gw.kvStore(conf.CacheStorage.Password)
	if err != nil {
		log.Fatalf("Could not retrieve cache storage password... %v", err)
	}

	conf.Security.PrivateCertificateEncodingSecret, err = gw.kvStore(conf.Security.PrivateCertificateEncodingSecret)
	if err != nil {
		log.Fatalf("Could not retrieve the private certificate encoding secret... %v", err)
	}

	if conf.UseDBAppConfigs {
		conf.DBAppConfOptions.ConnectionString, err = gw.kvStore(conf.DBAppConfOptions.ConnectionString)
		if err != nil {
			log.Fatalf("Could not fetch dashboard connection string.. %v", err)
		}
	}

	if conf.Policies.PolicySource == "service" {
		conf.Policies.PolicyConnectionString, err = gw.kvStore(conf.Policies.PolicyConnectionString)
		if err != nil {
			log.Fatalf("Could not fetch policy connection string... %v", err)
		}
	}

	gw.SetConfig(conf)
}

func (gw *Gateway) kvStore(value string) (string, error) {

	if strings.HasPrefix(value, "secrets://") {
		key := strings.TrimPrefix(value, "secrets://")
		log.Debugf("Retrieving %s from secret store in config", key)
		val, ok := gw.GetConfig().Secrets[key]
		if !ok {
			return "", fmt.Errorf("secrets does not exist in config.. %s not found", key)
		}

		return val, nil
	}

	if strings.HasPrefix(value, "env://") {
		key := strings.TrimPrefix(value, "env://")
		log.Debugf("Retrieving %s from environment", key)
		return os.Getenv(fmt.Sprintf("TYK_SECRET_%s", strings.ToUpper(key))), nil
	}

	if strings.HasPrefix(value, "consul://") {
		key := strings.TrimPrefix(value, "consul://")
		log.Debugf("Retrieving %s from consul", key)
		if err := gw.setUpConsul(); err != nil {
			log.Error("Failed to setup consul: ", err)

			// Return value as is. If consul cannot be set up
			return value, nil
		}

		return gw.consulKVStore.Get(key)
	}

	if strings.HasPrefix(value, "vault://") {
		key := strings.TrimPrefix(value, "vault://")
		log.Debugf("Retrieving %s from vault", key)
		if err := gw.setUpVault(); err != nil {
			log.Error("Failed to setup vault: ", err)
			// Return value as is If vault cannot be set up
			return value, nil
		}

		return gw.vaultKVStore.Get(key)
	}

	return value, nil
}

func (gw *Gateway) setUpVault() error {
	if gw.vaultKVStore != nil {
		return nil
	}

	var err error

	gw.vaultKVStore, err = kv.NewVault(gw.GetConfig().KV.Vault)
	if err != nil {
		log.Debugf("an error occurred while setting up vault... %v", err)
	}

	return err
}

func (gw *Gateway) setUpConsul() error {
	if gw.consulKVStore != nil {
		return nil
	}

	var err error

	gw.consulKVStore, err = kv.NewConsul(gw.GetConfig().KV.Consul)
	if err != nil {
		log.Debugf("an error occurred while setting up consul.. %v", err)
	}

	return err
}

func (gw *Gateway) getHostDetails(file string) {
	var err error
	if gw.hostDetails.PID, err = readPIDFromFile(file); err != nil {
		mainLog.Error("Failed ot get host pid: ", err)
	}
	if gw.hostDetails.Hostname, err = os.Hostname(); err != nil {
		mainLog.Error("Failed to get hostname: ", err)
	}
}

func (gw *Gateway) getGlobalMDCBStorageHandler(keyPrefix string, hashKeys bool) storage.Handler {
	localStorage := &storage.RedisCluster{KeyPrefix: keyPrefix, HashKeys: hashKeys, RedisController: gw.RedisController}
	logger := logrus.New().WithFields(logrus.Fields{"prefix": "mdcb-storage-handler"})

	if gw.GetConfig().SlaveOptions.UseRPC {
		return storage.NewMdcbStorage(
			localStorage,
			&RPCStorageHandler{
				KeyPrefix: keyPrefix,
				HashKeys:  hashKeys,
				Gw:        gw,
			},
			logger,
		)
	}
	return localStorage
}

func (gw *Gateway) getGlobalStorageHandler(keyPrefix string, hashKeys bool) storage.Handler {
	if gw.GetConfig().SlaveOptions.UseRPC {
		return &RPCStorageHandler{
			KeyPrefix: keyPrefix,
			HashKeys:  hashKeys,
			Gw:        gw,
		}
	}
	return &storage.RedisCluster{KeyPrefix: keyPrefix, HashKeys: hashKeys, RedisController: gw.RedisController}
}

func Start() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cli.Init(VERSION, confPaths)
	cli.Parse()
	// Stop gateway process if not running in "start" mode:
	if !cli.DefaultMode {
		os.Exit(0)
	}

	// ToDo:Config replace for get default conf
	gw := NewGateway(config.Default, ctx)
	gw.SetNodeID("solo-" + uuid.NewV4().String())

	gw.SessionID = uuid.NewV4().String()
	if err := gw.initialiseSystem(); err != nil {
		mainLog.Fatalf("Error initialising system: %v", err)
	}

	gwConfig := gw.GetConfig()
	if gwConfig.ControlAPIPort == 0 {
		mainLog.Warn("The control_api_port should be changed for production")
	}
	gw.setupPortsWhitelist()
	gw.keyGen = DefaultKeyGenerator{Gw: gw}

	onFork := func() {
		mainLog.Warning("PREPARING TO FORK")

		// if controlListener != nil {
		// 	if err := controlListener.Close(); err != nil {
		// 		mainLog.Error("Control listen handler exit: ", err)
		// 	}
		// 	mainLog.Info("Control listen closed")
		// }

		if gwConfig.UseDBAppConfigs {
			mainLog.Info("Stopping heartbeat")
			gw.DashService.StopBeating()
			mainLog.Info("Waiting to de-register")
			time.Sleep(10 * time.Second)

			os.Setenv("TYK_SERVICE_NONCE", gw.ServiceNonce)
			os.Setenv("TYK_SERVICE_NODEID", gw.GetNodeID())
		}
	}
	err := again.ListenFrom(&gw.DefaultProxyMux.again, onFork)
	if err != nil {
		mainLog.Errorf("Initializing again %s", err)
	}

	if tr := gwConfig.Tracer; tr.Enabled {
		trace.SetupTracing(tr.Name, tr.Options)
		trace.SetLogger(mainLog)
		defer trace.Close()
	}
	gw.start()
	configs := gw.GetConfig()
	go gw.RedisController.ConnectToRedis(gw.ctx, func() {
		gw.reloadURLStructure(func() {})
	}, &configs)

	if *cli.MemProfile {
		mainLog.Debug("Memory profiling active")
		var err error
		if memProfFile, err = os.Create("tyk.mprof"); err != nil {
			panic(err)
		}
		defer memProfFile.Close()
	}
	if *cli.CPUProfile {
		mainLog.Info("Cpu profiling active")
		cpuProfFile, err := os.Create("tyk.prof")
		if err != nil {
			panic(err)
		}
		pprof.StartCPUProfile(cpuProfFile)
		defer pprof.StopCPUProfile()
	}
	if *cli.BlockProfile {
		mainLog.Info("Block profiling active")
		runtime.SetBlockProfileRate(1)
	}
	if *cli.MutexProfile {
		mainLog.Info("Mutex profiling active")
		runtime.SetMutexProfileFraction(1)
	}

	// set var as global so we can export TykTriggerEvent(CEventName, CPayload *C.char)
	GatewayFireSystemEvent = gw.FireSystemEvent
	// TODO: replace goagain with something that support multiple listeners
	// Example: https://gravitational.com/blog/golang-ssh-bastion-graceful-restarts/
	gw.startServer()

	if again.Child() {
		// This is a child process, we need to murder the parent now
		if err := again.Kill(); err != nil {
			mainLog.Fatal(err)
		}
	}
	_, err = again.Wait(&gw.DefaultProxyMux.again)
	if err != nil {
		mainLog.WithError(err).Error("waiting")
	}
	mainLog.Info("Stop signal received.")
	if err = gw.DefaultProxyMux.again.Close(); err != nil {
		mainLog.Error("Closing listeners: ", err)
	}
	// stop analytics workers
	if gwConfig.EnableAnalytics && gw.Analytics.Store == nil {
		gw.Analytics.Stop()
	}

	// write pprof profiles
	writeProfiles()

	if gwConfig.UseDBAppConfigs {
		mainLog.Info("Stopping heartbeat...")
		gw.DashService.StopBeating()
		time.Sleep(2 * time.Second)
		err := gw.DashService.DeRegister()
		if err != nil {
			mainLog.WithError(err).Error("deregistering in dashboard")
		}
	}

	mainLog.Info("Terminating.")

	time.Sleep(time.Second)
}

func writeProfiles() {
	if *cli.BlockProfile {
		f, err := os.Create("tyk.blockprof")
		if err != nil {
			panic(err)
		}
		if err = pprof.Lookup("block").WriteTo(f, 0); err != nil {
			panic(err)
		}
		f.Close()
	}
	if *cli.MutexProfile {
		f, err := os.Create("tyk.mutexprof")
		if err != nil {
			panic(err)
		}
		if err = pprof.Lookup("mutex").WriteTo(f, 0); err != nil {
			panic(err)
		}
		f.Close()
	}
}

func (gw *Gateway) start() {
	// Set up a default org manager so we can traverse non-live paths
	if !gw.GetConfig().SupressDefaultOrgStore {
		mainLog.Debug("Initialising default org store")
		gw.DefaultOrgStore.Init(gw.getGlobalStorageHandler("orgkey.", false))
		//DefaultQuotaStore.Init(getGlobalStorageHandler(CloudHandler, "orgkey.", false))
		gw.DefaultQuotaStore.Init(gw.getGlobalStorageHandler("orgkey.", false))
	}

	// Start listening for reload messages
	if !gw.GetConfig().SuppressRedisSignalReload {
		go gw.startPubSubLoop()
	}

	if slaveOptions := gw.GetConfig().SlaveOptions; slaveOptions.UseRPC {
		mainLog.Debug("Starting RPC reload listener")
		gw.RPCListener = RPCStorageHandler{
			KeyPrefix:        "rpc.listener.",
			SuppressRegister: true,
			Gw:               gw,
		}

		gw.RPCListener.Connect()
		go gw.rpcReloadLoop(slaveOptions.RPCKey)
		go gw.RPCListener.StartRPCKeepaliveWatcher()
		go gw.RPCListener.StartRPCLoopCheck(slaveOptions.RPCKey)
	}

	// 1s is the minimum amount of time between hot reloads. The
	// interval counts from the start of one reload to the next.
	go gw.reloadLoop(time.Tick(time.Second))
	go gw.reloadQueueLoop()
}

func dashboardServiceInit(gw *Gateway) {
	if gw.DashService == nil {
		gw.DashService = &HTTPDashboardHandler{Gw: gw}
		err := gw.DashService.Init()
		if err != nil {
			mainLog.WithError(err).Error("Initiating dashboard service")
		}
	}
}

func handleDashboardRegistration(gw *Gateway) {
	if !gw.GetConfig().UseDBAppConfigs {
		return
	}

	dashboardServiceInit(gw)

	// connStr := buildDashboardConnStr("/register/node")
	if err := gw.DashService.Register(); err != nil {
		dashLog.Fatal("Registration failed: ", err)
	}

	go func() {
		beatErr := gw.DashService.StartBeating()
		if beatErr != nil {
			dashLog.Error("Could not start beating. ", beatErr.Error())
		}
	}()
}

func (gw *Gateway) startDRL() {
	switch {
	case gw.GetConfig().ManagementNode:
		return
	case gw.GetConfig().EnableSentinelRateLimiter, gw.GetConfig().EnableRedisRollingLimiter:
		return
	}
	mainLog.Info("Initialising distributed rate limiter")
	gw.setupDRL()
	gw.startRateLimitNotifications()
}

func (gw *Gateway) setupPortsWhitelist() {
	// setup listen and control ports as whitelisted
	gwConf := gw.GetConfig()
	w := gwConf.PortWhiteList
	if w == nil {
		w = make(map[string]config.PortWhiteList)
	}
	protocol := "http"
	if gwConf.HttpServerOptions.UseSSL {
		protocol = "https"
	}
	ls := config.PortWhiteList{}
	if v, ok := w[protocol]; ok {
		ls = v
	}
	ls.Ports = append(ls.Ports, gwConf.ListenPort)
	if gwConf.ControlAPIPort != 0 {
		ls.Ports = append(ls.Ports, gwConf.ControlAPIPort)
	}
	w[protocol] = ls
	gwConf.PortWhiteList = w
	gw.SetConfig(gwConf)
}

func (gw *Gateway) startServer() {
	// Ensure that Control listener and default http listener running on first start
	muxer := &proxyMux{}

	router := mux.NewRouter()
	gw.loadControlAPIEndpoints(router)

	muxer.setRouter(gw.GetConfig().ControlAPIPort, "", router, gw.GetConfig())

	if muxer.router(gw.GetConfig().ListenPort, "", gw.GetConfig()) == nil {
		muxer.setRouter(gw.GetConfig().ListenPort, "", mux.NewRouter(), gw.GetConfig())
	}
	gw.DefaultProxyMux.swap(muxer, gw)
	// handle dashboard registration and nonces if available
	handleDashboardRegistration(gw)

	gw.DRLManager = &drl.DRL{}
	// at this point NodeID is ready to use by DRL
	gw.drlOnce.Do(gw.startDRL)

	mainLog.Infof("Tyk Gateway started (%s)", VERSION)
	address := gw.GetConfig().ListenAddress
	if gw.GetConfig().ListenAddress == "" {
		address = "(open interface)"
	}

	mainLog.Info("--> Listening on address: ", address)
	mainLog.Info("--> Listening on port: ", gw.GetConfig().ListenPort)
	mainLog.Info("--> PID: ", gw.hostDetails.PID)
	if !rpc.IsEmergencyMode() {
		gw.DoReload()
	}
}

func (gw *Gateway) GetConfig() config.Config {
	return gw.config.Load().(config.Config)
}

func (gw *Gateway) SetConfig(conf config.Config) {
	gw.configMu.Lock()
	defer gw.configMu.Unlock()
	gw.config.Store(conf)
}

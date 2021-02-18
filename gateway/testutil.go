package gateway

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jensneuse/graphql-go-tools/pkg/execution/datasource"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"

	"golang.org/x/net/context"

	"github.com/TykTechnologies/tyk/apidef"

	"github.com/TykTechnologies/tyk/cli"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
	_ "github.com/TykTechnologies/tyk/templates" // Don't delete
	"github.com/TykTechnologies/tyk/test"
	_ "github.com/TykTechnologies/tyk/testdata" // Don't delete
	"github.com/TykTechnologies/tyk/user"
	uuid "github.com/satori/go.uuid"
)

var (
	// to register to, but never used
	discardMuxer = mux.NewRouter()

	// Used to store the test bundles:
	testMiddlewarePath, _ = ioutil.TempDir("", "tyk-middleware-path")

	mockHandle *test.DnsMockHandle

	testServerRouter  *mux.Router
	defaultTestConfig config.Config

	EnableTestDNSMock = true

	// ReloadTestCase use this when in any test for gateway reloads
	ReloadTestCase = NewReloadMachinery()
	// OnConnect this is a callback which is called whenever we transition redis Disconnected to connected
	OnConnect func()
)

// ReloadMachinery is a helper struct to use when writing tests that do manual
// gateway reloads
type ReloadMachinery struct {
	run    bool
	count  int
	cycles int
	mu     sync.RWMutex

	// to simulate time ticks for tests that do reloads
	reloadTick chan time.Time
	stop       chan struct{}
}

func NewReloadMachinery() *ReloadMachinery {
	return &ReloadMachinery{
		reloadTick: make(chan time.Time),
	}
}

func (r *ReloadMachinery) StartTicker() {
	r.stop = make(chan struct{})

	go func() {
		for {
			select {
			case <-r.stop:
				return
			default:
				r.Tick()
			}
		}
	}()
}

func (r *ReloadMachinery) StopTicker() {
	close(r.stop)
}

func (r *ReloadMachinery) ReloadTicker() <-chan time.Time {
	return r.reloadTick
}

// OnQueued is called when a reload has been queued. This increments the queue
// count
func (r *ReloadMachinery) OnQueued() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.run {
		r.count++
	}
}

// OnReload is called when a reload has been completed. This increments the
// reload cycles count.
func (r *ReloadMachinery) OnReload() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.run {
		r.cycles++
	}
}

// Reloaded returns true if a read has occured since r was enabled
func (r *ReloadMachinery) Reloaded() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cycles > 0
}

// Enable  when callled it will allow r to keep track of reload cycles and queues
func (r *ReloadMachinery) Enable() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.run = true
}

// Disable turns off tracking of reload cycles and queues
func (r *ReloadMachinery) Disable() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.run = true
	r.count = 0
	r.cycles = 0
}

// Reset sets reloads counts and queues to 0
func (r *ReloadMachinery) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.count = 0
	r.cycles = 0
}

// Queued returns true if any queue happened
func (r *ReloadMachinery) Queued() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.count > 0
}

// EnsureQueued this will block until any queue happens. It will timeout after
// 100ms
func (r *ReloadMachinery) EnsureQueued(t *testing.T) {
	deadline := time.NewTimer(100 * time.Millisecond)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatal("Timedout waiting for reload to be queue")
		case <-tick.C:
			if r.Queued() {
				return
			}
		}
	}
}

// EnsureReloaded this will block until any reload happens. It will timeout after
// 100ms
func (r *ReloadMachinery) EnsureReloaded(t *testing.T) {
	deadline := time.NewTimer(100 * time.Millisecond)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatal("Timedout waiting for reload to be queue")
		case <-tick.C:
			if r.Reloaded() {
				return
			}
		}
	}
}

// Tick triggers reload
func (r *ReloadMachinery) Tick() {
	r.reloadTick <- time.Time{}
}

// TickOk triggers a reload and ensures a queue happend and a reload cycle
// happens. This will block until all the cases are met.
func (r *ReloadMachinery) TickOk(t *testing.T) {
	r.EnsureQueued(t)
	r.Tick()
	r.EnsureReloaded(t)
}

func InitTestMain(ctx context.Context, m *testing.M, genConf ...func(globalConf *config.Config)) int {
	setTestMode(true)
	testServerRouter = testHttpHandler()
	testServer := &http.Server{
		Addr:           testHttpListen,
		Handler:        testServerRouter,
		ReadTimeout:    1 * time.Second,
		WriteTimeout:   1 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	globalConf := config.Global()
	if err := config.WriteDefault("", &globalConf); err != nil {
		panic(err)
	}
	globalConf.Storage.Database = rand.Intn(15)
	var err error
	globalConf.AppPath, err = ioutil.TempDir("", "tyk-test-")
	if err != nil {
		panic(err)
	}
	globalConf.EnableAnalytics = true
	globalConf.AnalyticsConfig.EnableGeoIP = true
	_, b, _, _ := runtime.Caller(0)
	gatewayPath := filepath.Dir(b)
	rootPath := filepath.Dir(gatewayPath)
	globalConf.AnalyticsConfig.GeoIPDBLocation = filepath.Join(rootPath, "testdata", "MaxMind-DB-test-ipv4-24.mmdb")
	globalConf.EnableJSVM = true
	globalConf.HashKeyFunction = storage.HashMurmur64
	globalConf.Monitor.EnableTriggerMonitors = true
	globalConf.AnalyticsConfig.NormaliseUrls.Enabled = true
	globalConf.AllowInsecureConfigs = true
	// Enable coprocess and bundle downloader:
	globalConf.CoProcessOptions.EnableCoProcess = true
	globalConf.EnableBundleDownloader = true
	globalConf.BundleBaseURL = testHttpBundles
	globalConf.MiddlewarePath = testMiddlewarePath
	// force ipv4 for now, to work around the docker bug affecting
	// Go 1.8 and ealier
	globalConf.ListenAddress = "127.0.0.1"
	if len(genConf) > 0 {
		genConf[0](&globalConf)
	}

	if EnableTestDNSMock {
		mockHandle, err = test.InitDNSMock(test.DomainsToAddresses, nil)
		if err != nil {
			panic(err)
		}

		defer mockHandle.ShutdownDnsMock()
	}

	go func() {
		err := testServer.ListenAndServe()
		if err != nil {
			log.Warn("testServer.ListenAndServe() err: ", err.Error())
		}
	}()

	defer testServer.Shutdown(context.Background())

	CoProcessInit()
	afterConfSetup(&globalConf)
	defaultTestConfig = globalConf
	config.SetGlobal(globalConf)
	if err := emptyRedis(); err != nil {
		panic(err)
	}
	cli.Init(VERSION, confPaths)
	initialiseSystem(ctx)
	// Small part of start()
	loadControlAPIEndpoints(mainRouter())
	if analytics.GeoIPDB == nil {
		panic("GeoIPDB was not initialized")
	}
	go storage.ConnectToRedis(ctx, func() {
		if OnConnect != nil {
			OnConnect()
		}
	})
	for {
		if storage.Connected() {
			break
		}

		time.Sleep(10 * time.Millisecond)
	}
	go startPubSubLoop()
	go reloadLoop(ctx, ReloadTestCase.ReloadTicker(), ReloadTestCase.OnReload)
	go reloadQueueLoop(ctx, ReloadTestCase.OnQueued)
	go reloadSimulation()
	exitCode := m.Run()
	os.RemoveAll(config.Global().AppPath)
	return exitCode
}

func ResetTestConfig() {
	config.SetGlobal(defaultTestConfig)
}

func emptyRedis() error {
	ctx := context.Background()
	addr := config.Global().Storage.Host + ":" + strconv.Itoa(config.Global().Storage.Port)
	c := redis.NewClient(&redis.Options{Addr: addr})
	defer c.Close()
	dbName := strconv.Itoa(config.Global().Storage.Database)
	if err := c.Do(ctx, "SELECT", dbName).Err(); err != nil {
		return err
	}
	err := c.FlushDB(ctx).Err()
	return err
}

// simulate reloads in the background, i.e. writes to
// global variables that should not be accessed in a
// racy way like the policies and api specs maps.
func reloadSimulation() {
	for {
		policiesMu.Lock()
		policiesByID["_"] = user.Policy{}
		delete(policiesByID, "_")
		policiesMu.Unlock()
		apisMu.Lock()
		old := apiSpecs
		apiSpecs = append(apiSpecs, nil)
		apiSpecs = old
		apisByID["_"] = nil
		delete(apisByID, "_")
		apisMu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
}

// map[bundleName]map[fileName]fileContent
var testBundles = map[string]map[string]string{}
var testBundleMu sync.Mutex

func RegisterBundle(name string, files map[string]string) string {
	testBundleMu.Lock()
	defer testBundleMu.Unlock()

	bundleID := name + "-" + uuid.NewV4().String() + ".zip"
	testBundles[bundleID] = files

	return bundleID
}

func RegisterJSFileMiddleware(apiid string, files map[string]string) {
	os.MkdirAll(config.Global().MiddlewarePath+"/"+apiid+"/post", 0755)
	os.MkdirAll(config.Global().MiddlewarePath+"/"+apiid+"/pre", 0755)

	for file, content := range files {
		ioutil.WriteFile(config.Global().MiddlewarePath+"/"+apiid+"/"+file, []byte(content), 0755)
	}
}

func bundleHandleFunc(w http.ResponseWriter, r *http.Request) {
	testBundleMu.Lock()
	defer testBundleMu.Unlock()

	bundleName := strings.Replace(r.URL.Path, "/bundles/", "", -1)
	bundle, exists := testBundles[bundleName]
	if !exists {
		log.Warning(testBundles)
		http.Error(w, "Bundle not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/zip")

	z := zip.NewWriter(w)
	for name, content := range bundle {
		f, _ := z.Create(name)
		f.Write([]byte(content))
	}
	z.Close()
}
func mainRouter() *mux.Router {
	return getMainRouter(defaultProxyMux)
}

func mainProxy() *proxy {
	return defaultProxyMux.getProxy(config.Global().ListenPort)
}

func controlProxy() *proxy {
	p := defaultProxyMux.getProxy(config.Global().ControlAPIPort)
	if p != nil {
		return p
	}
	return mainProxy()
}

func EnablePort(port int, protocol string) {
	c := config.Global()
	if c.PortWhiteList == nil {
		c.PortWhiteList = map[string]config.PortWhiteList{
			protocol: {
				Ports: []int{port},
			},
		}
	} else {
		m, ok := c.PortWhiteList[protocol]
		if !ok {
			m = config.PortWhiteList{
				Ports: []int{port},
			}
		} else {
			m.Ports = append(m.Ports, port)
		}
		c.PortWhiteList[protocol] = m
	}
	config.SetGlobal(c)
}

func getMainRouter(m *proxyMux) *mux.Router {
	var protocol string
	if config.Global().HttpServerOptions.UseSSL {
		protocol = "https"
	} else {
		protocol = "http"
	}
	return m.router(config.Global().ListenPort, protocol)
}

type TestHttpResponse struct {
	Method  string
	URI     string
	Url     string
	Body    string
	Headers map[string]string
	Form    map[string]string
}

// ProxyHandler Proxies requests through to their final destination, if they make it through the middleware chain.
func ProxyHandler(p *ReverseProxy, apiSpec *APISpec) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseMid := BaseMiddleware{Spec: apiSpec, Proxy: p}
		handler := SuccessHandler{baseMid}
		// Skip all other execution
		handler.ServeHTTP(w, r)
	})
}

const (
	handlerPathRestDataSource        = "/rest-data-source"
	handlerPathGraphQLDataSource     = "/graphql-data-source"
	handlerPathHeadersRestDataSource = "/rest-headers-data-source"

	// We need a static port so that the urls can be used in static
	// test data, and to prevent the requests from being randomized
	// for checksums. Port 16500 should be obscure and unused.
	testHttpListen = "127.0.0.1:16500"
	// Accepts any http requests on /, only allows GET on /get, etc.
	// All return a JSON with request info.
	TestHttpAny               = "http://" + testHttpListen
	TestHttpGet               = TestHttpAny + "/get"
	testHttpPost              = TestHttpAny + "/post"
	testGraphQLDataSource     = TestHttpAny + handlerPathGraphQLDataSource
	testRESTDataSource        = TestHttpAny + handlerPathRestDataSource
	testRESTHeadersDataSource = TestHttpAny + handlerPathHeadersRestDataSource
	testHttpJWK               = TestHttpAny + "/jwk.json"
	testHttpJWKLegacy         = TestHttpAny + "/jwk-legacy.json"
	testHttpBundles           = TestHttpAny + "/bundles/"
	testReloadGroup           = TestHttpAny + "/groupReload"

	// Nothing should be listening on port 16501 - useful for
	// testing TCP and HTTP failures.
	testHttpFailure       = "127.0.0.1:16501"
	testHttpFailureAny    = "http://" + testHttpFailure
	MockOrgID             = "507f1f77bcf86cd799439011"
	NonCanonicalHeaderKey = "X-CertificateOuid"
)

func testHttpHandler() *mux.Router {
	var upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	wsHandler := func(w http.ResponseWriter, req *http.Request) {
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			http.Error(w, fmt.Sprintf("cannot upgrade: %v", err), http.StatusInternalServerError)
		}

		// start simple reader/writer per connection
		go func() {
			for {
				mt, p, err := conn.ReadMessage()
				if err != nil {
					return
				}
				conn.WriteMessage(mt, []byte("reply to message: "+string(p)))
			}
		}()
	}

	httpError := func(w http.ResponseWriter, status int) {
		http.Error(w, http.StatusText(status), status)
	}
	writeDetails := func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			httpError(w, http.StatusInternalServerError)
			return
		}
		r.URL.Opaque = r.URL.RawPath
		w.Header().Set("X-Tyk-Test", "1")
		body, _ := ioutil.ReadAll(r.Body)

		err := json.NewEncoder(w).Encode(TestHttpResponse{
			Method:  r.Method,
			URI:     r.RequestURI,
			Url:     r.URL.String(),
			Headers: firstVals(r.Header),
			Form:    firstVals(r.Form),
			Body:    string(body),
		})
		if err != nil {
			httpError(w, http.StatusInternalServerError)
		}
	}
	handleMethod := func(method string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if method != "" && r.Method != method {
				httpError(w, http.StatusMethodNotAllowed)
			} else {
				writeDetails(w, r)
			}
		}
	}

	// use gorilla's mux as it allows to cancel URI cleaning
	// (it is not configurable in standard http mux)
	r := mux.NewRouter()

	r.HandleFunc("/get", handleMethod("GET"))
	r.HandleFunc("/post", handleMethod("POST"))

	r.HandleFunc(handlerPathGraphQLDataSource, graphqlDataSourceHandler)
	r.HandleFunc(handlerPathRestDataSource, restDataSourceHandler)
	r.HandleFunc(handlerPathHeadersRestDataSource, restHeadersDataSourceHandler)

	r.HandleFunc("/ws", wsHandler)
	r.HandleFunc("/jwk.json", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, jwkTestJson)
	})
	r.HandleFunc("/jwk-legacy.json", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, jwkTestJsonLegacy)
	})

	r.HandleFunc("/compressed", func(w http.ResponseWriter, r *http.Request) {
		response := "This is a compressed response"
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		json.NewEncoder(gz).Encode(response)
		gz.Close()
	})
	r.HandleFunc("/groupReload", groupResetHandler)
	r.HandleFunc("/bundles/{rest:.*}", bundleHandleFunc)
	r.HandleFunc("/errors/{status}", func(w http.ResponseWriter, r *http.Request) {
		statusCode, _ := strconv.Atoi(mux.Vars(r)["status"])
		httpError(w, statusCode)
	})
	r.HandleFunc("/{rest:.*}", handleMethod(""))

	return r
}

func graphqlDataSourceHandler(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte(`{
			"data": {
				"countries": [
					{	
						"code": "TR",
						"name": "Turkey"	
					},
					{
						"code": "RU",
						"name": "Russia"
					},
					{
						"code": "GB",
						"name": "United Kingdom"
					},
					{
						"code": "DE",
						"name": "Germany"
					}
				]
			}
		}`))
}

func restHeadersDataSourceHandler(w http.ResponseWriter, r *http.Request) {
	type KeyVal struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}

	var headers []KeyVal
	for name, values := range r.Header {
		for _, value := range values {
			headers = append(headers, KeyVal{name, value})
		}
	}
	json.NewEncoder(w).Encode(headers)
}

func restDataSourceHandler(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte(`[
			{
				"name": "Furkan",
				"country":  {
					"name": "Turkey"
				}
			},
			{
				"name": "Leo",
				"country":  {
					"name": "Russia"
				}
			},
			{
				"name": "Josh",
				"country":  {
					"name": "UK"
				}
			},
			{
				"name": "Patric",
				"country":  {
					"name": "Germany"
				}
			}
		]`))
}

const jwkTestJson = `{
    "keys": [
        {
            "use": "sig",
            "kty": "RSA",
            "kid": "12345",
            "alg": "RS256",
            "n": "yqZ4rwKF8qCExS7kpY4cnJa_37FMkJNkalZ3OuslLB0oRL8T4c94kdF4aeNzSFkSe2n99IBI6Ssl79vbfMZb-t06L0Q94k-_P37x7-_RJZiff4y1VGjrnrnMI2iu9l4iBBRYzNmG6eblroEMMWlgk5tysHgxB59CSNIcD9gqk1hx4n_FgOmvKsfQgWHNlPSDTRcWGWGhB2_XgNVYG2pOlQxAPqLhBHeqGTXBbPfGF9cHzixpsPr6GtbzPwhsQ_8bPxoJ7hdfn-rzztks3d6-HWURcyNTLRe0mjXjjee9Z6-gZ-H-fS4pnP9tqT7IgU6ePUWTpjoiPtLexgsAa_ctjQ",
            "e": "AQAB"
        }
    ]
}`

const jwkTestJsonLegacy = `{
    "keys": [{
        "alg": "RS256",
        "kty": "RSA",
        "use": "sig",
        "x5c": ["Ci0tLS0tQkVHSU4gUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBeXFaNHJ3S0Y4cUNFeFM3a3BZNGMKbkphLzM3Rk1rSk5rYWxaM091c2xMQjBvUkw4VDRjOTRrZEY0YWVOelNGa1NlMm45OUlCSTZTc2w3OXZiZk1aYgordDA2TDBROTRrKy9QMzd4NysvUkpaaWZmNHkxVkdqcm5ybk1JMml1OWw0aUJCUll6Tm1HNmVibHJvRU1NV2xnCms1dHlzSGd4QjU5Q1NOSWNEOWdxazFoeDRuL0ZnT212S3NmUWdXSE5sUFNEVFJjV0dXR2hCMi9YZ05WWUcycE8KbFF4QVBxTGhCSGVxR1RYQmJQZkdGOWNIeml4cHNQcjZHdGJ6UHdoc1EvOGJQeG9KN2hkZm4rcnp6dGtzM2Q2KwpIV1VSY3lOVExSZTBtalhqamVlOVo2K2daK0grZlM0cG5QOXRxVDdJZ1U2ZVBVV1Rwam9pUHRMZXhnc0FhL2N0CmpRSURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo="],
        "n": "xofiG8gsnv9-I_g-5OWTLhaZtgAGq1QEsBCPK9lmLqhuonHe8lT-nK1DM49f6J9QgaOjZ3DB50QkhBysnIFNcXFyzaYIPMoccvuHLPgdBawX4WYKm5gficD0WB0XnTt4sqTI5usFpuop9vvW44BwVGhRqMT7c11gA8TSWMBxDI4A5ARc4MuQtfm64oN-JQodSztArwb9wcmH8WrBvSUkR4pyi9MT8W27gqJ2e2Xn8jgGnswNQWOyCTN84PawOYaN-2ORHeIea1g-URln1bofcHN73vZCIrVbE6iA2D7Ybh22AVrCfunekEDEe2GZfLZLejiZiBWG7enJhcrQIzAQGw",
        "e": "AQAB",
        "kid": "12345",
        "x5t": "12345"
    }]
}`

func withAuth(r *http.Request) *http.Request {
	// This is the default config secret
	r.Header.Set("x-tyk-authorization", config.Global().Secret)
	return r
}

// Deprecated: Use Test.CreateSession instead.
func CreateSession(sGen ...func(s *user.SessionState)) string {
	key := generateToken("default", "")
	session := CreateStandardSession()
	if len(sGen) > 0 {
		sGen[0](session)
	}
	if session.Certificate != "" {
		key = generateToken("default", session.Certificate)
	}

	GlobalSessionManager.UpdateSession(storage.HashKey(key), session, 60, config.Global().HashKeys)
	return key
}

func CreateStandardSession() *user.SessionState {
	session := user.NewSessionState()
	session.Rate = 10000
	session.Allowance = session.Rate
	session.LastCheck = time.Now().Unix()
	session.Per = 60
	session.Expires = -1
	session.QuotaRenewalRate = 300 // 5 minutes
	session.QuotaRenews = time.Now().Unix() + 20
	session.QuotaRemaining = 10
	session.QuotaMax = -1
	session.Tags = []string{}
	session.MetaData = make(map[string]interface{})
	session.OrgID = "default"
	return session
}

func CreateStandardPolicy() *user.Policy {
	return &user.Policy{
		OrgID:            "default",
		Rate:             1000.0,
		Per:              1.0,
		QuotaMax:         -1,
		QuotaRenewalRate: -1,
		AccessRights:     map[string]user.AccessDefinition{},
		Active:           true,
		KeyExpiresIn:     60,
	}
}

func CreatePolicy(pGen ...func(p *user.Policy)) string {
	pID := keyGen.GenerateAuthKey("")
	pol := CreateStandardPolicy()
	pol.ID = pID

	if len(pGen) > 0 {
		pGen[0](pol)
	}

	policiesMu.Lock()
	policiesByID[pol.ID] = *pol
	policiesMu.Unlock()

	return pol.ID
}

func CreateJWKToken(jGen ...func(*jwt.Token)) string {
	// Create the token
	token := jwt.New(jwt.GetSigningMethod("RS512"))
	// Set the token ID

	if len(jGen) > 0 {
		jGen[0](token)
	}

	// Sign and get the complete encoded token as a string
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(jwtRSAPrivKey))
	if err != nil {
		panic("Couldn't extract private key: " + err.Error())
	}
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		panic("Couldn't create JWT token: " + err.Error())
	}

	return tokenString
}

func CreateJWKTokenECDSA(jGen ...func(*jwt.Token)) string {
	// Create the token
	token := jwt.New(jwt.GetSigningMethod("ES256"))
	// Set the token ID

	if len(jGen) > 0 {
		jGen[0](token)
	}

	// Sign and get the complete encoded token as a string
	signKey, err := jwt.ParseECPrivateKeyFromPEM([]byte(jwtECDSAPrivateKey))
	if err != nil {
		panic("Couldn't extract private key: " + err.Error())
	}
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		panic("Couldn't create JWT token: " + err.Error())
	}

	return tokenString
}

func createJWKTokenHMAC(jGen ...func(*jwt.Token)) string {
	// Create the token
	token := jwt.New(jwt.SigningMethodHS256)
	// Set the token ID

	if len(jGen) > 0 {
		jGen[0](token)
	}

	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		panic("Couldn't create JWT token: " + err.Error())
	}

	return tokenString
}

func TestReqBody(t testing.TB, body interface{}) io.Reader {
	switch x := body.(type) {
	case []byte:
		return bytes.NewReader(x)
	case string:
		return strings.NewReader(x)
	case io.Reader:
		return x
	case nil:
		return nil
	default: // JSON objects (structs)
		bs, err := json.Marshal(x)
		if err != nil {
			t.Fatal(err)
		}
		return bytes.NewReader(bs)
	}
}

func TestReq(t testing.TB, method, urlStr string, body interface{}) *http.Request {
	return httptest.NewRequest(method, urlStr, TestReqBody(t, body))
}

func CreateDefinitionFromString(defStr string) *APISpec {
	loader := APIDefinitionLoader{}
	def := loader.ParseDefinition(strings.NewReader(defStr))
	spec := loader.MakeSpec(def, nil)
	return spec
}

func LoadSampleAPI(def string) (spec *APISpec) {
	spec = CreateDefinitionFromString(def)
	loadApps([]*APISpec{spec})
	return
}

func firstVals(vals map[string][]string) map[string]string {
	m := make(map[string]string, len(vals))
	for k, vs := range vals {
		m[k] = vs[0]
	}
	return m
}

type TestConfig struct {
	SeparateControlAPI bool
	Delay              time.Duration
	HotReload          bool
	overrideDefaults   bool
	CoprocessConfig    config.CoProcessConfig
}

type Test struct {
	URL string

	testRunner   *test.HTTPTestRunner
	GlobalConfig config.Config
	config       TestConfig
	cacnel       func()
}

func (s *Test) Start() {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	_, port, _ := net.SplitHostPort(l.Addr().String())
	l.Close()
	globalConf := config.Global()
	globalConf.ListenPort, _ = strconv.Atoi(port)

	if s.config.SeparateControlAPI {
		l, _ := net.Listen("tcp", "127.0.0.1:0")

		_, port, _ = net.SplitHostPort(l.Addr().String())
		l.Close()
		globalConf.ControlAPIPort, _ = strconv.Atoi(port)
	}
	globalConf.CoProcessOptions = s.config.CoprocessConfig
	config.SetGlobal(globalConf)

	setupPortsWhitelist()

	startServer()
	ctx, cancel := context.WithCancel(context.Background())
	s.cacnel = cancel
	setupGlobals(ctx)
	// Set up a default org manager so we can traverse non-live paths
	if !config.Global().SupressDefaultOrgStore {
		DefaultOrgStore.Init(getGlobalStorageHandler("orgkey.", false))
		DefaultQuotaStore.Init(getGlobalStorageHandler("orgkey.", false))
	}

	s.GlobalConfig = globalConf

	scheme := "http://"
	if s.GlobalConfig.HttpServerOptions.UseSSL {
		scheme = "https://"
	}
	s.URL = scheme + mainProxy().listener.Addr().String()

	s.testRunner = &test.HTTPTestRunner{
		RequestBuilder: func(tc *test.TestCase) (*http.Request, error) {
			tc.BaseURL = s.URL
			if tc.ControlRequest {
				if s.config.SeparateControlAPI {
					tc.BaseURL = scheme + controlProxy().listener.Addr().String()
				} else if s.GlobalConfig.ControlAPIHostname != "" {
					tc.Domain = s.GlobalConfig.ControlAPIHostname
				}
			}
			r, err := test.NewRequest(tc)

			if tc.AdminAuth {
				r = withAuth(r)
			}

			if s.config.Delay > 0 {
				tc.Delay = s.config.Delay
			}

			return r, err
		},
		Do: test.HttpServerRunner(),
	}
}

func (s *Test) Do(tc test.TestCase) (*http.Response, error) {
	req, _ := s.testRunner.RequestBuilder(&tc)
	return s.testRunner.Do(req, &tc)
}

func (s *Test) Close() {
	if s.cacnel != nil {
		s.cacnel()
	}
	defaultProxyMux.swap(&proxyMux{})
	if s.config.SeparateControlAPI {
		globalConf := config.Global()
		globalConf.ControlAPIPort = 0
		config.SetGlobal(globalConf)
	}
}

func (s *Test) Run(t testing.TB, testCases ...test.TestCase) (*http.Response, error) {
	t.Helper()
	return s.testRunner.Run(t, testCases...)
}

//TODO:(gernest) when hot reload is suppored enable this.
func (s *Test) RunExt(t testing.TB, testCases ...test.TestCase) {
	s.Run(t, testCases...)
	var testMatrix = []struct {
		goagain          bool
		overrideDefaults bool
	}{
		{false, false},
		{false, true},
		{true, true},
		{true, false},
	}

	for i, m := range testMatrix {
		s.config.HotReload = m.goagain
		s.config.overrideDefaults = m.overrideDefaults

		if i > 0 {
			s.Close()
			s.Start()
		}

		title := fmt.Sprintf("hotReload: %v, overrideDefaults: %v", m.goagain, m.overrideDefaults)
		t.(*testing.T).Run(title, func(t *testing.T) {
			s.Run(t, testCases...)
		})
	}
}

func GetTLSClient(cert *tls.Certificate, caCert []byte) *http.Client {
	// Setup HTTPS client
	tlsConfig := &tls.Config{}

	if cert != nil {
		tlsConfig.Certificates = []tls.Certificate{*cert}
	}

	if len(caCert) > 0 {
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
		tlsConfig.BuildNameToCertificate()
	} else {
		tlsConfig.InsecureSkipVerify = true
	}

	transport := &http.Transport{TLSClientConfig: tlsConfig}

	return &http.Client{Transport: transport}
}

func (s *Test) CreateSession(sGen ...func(s *user.SessionState)) (*user.SessionState, string) {
	session := CreateStandardSession()
	if len(sGen) > 0 {
		sGen[0](session)
	}

	client := GetTLSClient(nil, nil)

	resp, err := s.Do(test.TestCase{
		Method:    http.MethodPost,
		Path:      "/tyk/keys/create",
		Data:      session,
		Client:    client,
		AdminAuth: true,
	})

	if err != nil {
		log.Fatal("Error while creating session:", err)
		return nil, ""
	}

	keySuccess := apiModifyKeySuccess{}
	err = json.NewDecoder(resp.Body).Decode(&keySuccess)
	if err != nil {
		log.Fatal("Error while decoding session response:", err)
		return nil, ""
	}

	createdSession, _ := GlobalSessionManager.SessionDetail(session.OrgID, keySuccess.Key, false)

	return &createdSession, keySuccess.Key
}

func StartTest(config ...TestConfig) *Test {
	t := &Test{}
	if len(config) > 0 {
		t.config = config[0]
	}
	t.Start()

	return t
}

const sampleAPI = `{
    "api_id": "test",
	"org_id": "default",
    "use_keyless": true,
    "definition": {
        "location": "header",
        "key": "version"
    },
    "auth": {
        "auth_header_name": "authorization"
	},
    "version_data": {
		"default_version": "Default",
        "not_versioned": true,
        "versions": {
            "v1": {
            	"name": "v1",
            	"use_extended_paths": true
           	}
        }
    },
    "proxy": {
        "listen_path": "/sample",
        "target_url": "` + TestHttpAny + `"
    },
	"graphql": {
      "enabled": false,
      "execution_mode": "executionEngine",
	  "version": "",
      "schema": "` + testComposedSchema + `",
      "type_field_configurations": [
        ` + testGraphQLDataSourceConfiguration + `,
        ` + testRESTDataSourceConfiguration + `
      ],
	  "engine": {
		"field_configs": [
			{
				"type_name": "Query",
				"field_name": "people",
				"disable_default_mapping": true,
				"path": [""]
			},
			{
				"type_name": "Query",
				"field_name": "headers",
				"disable_default_mapping": true,
				"path": [""]
			}
		],
		"data_sources": [
		    ` + testRESTDataSourceConfigurationV2 + `,
			` + testGraphQLDataSourceConfigurationV2 + `,
			` + testRESTHeadersDataSourceConfigurationV2 + `
		]
	},
      "playground": {
        "enabled": false,
        "path": "/playground"
      }
    }
}`

const testComposedSchema = "type Query {people: [Person] countries: [Country] headers: [Header]} " +
	"type Person {name: String country: Country} " +
	"type Country {code: String name: String} " +
	"type Header {name:String value: String}"

const testGraphQLDataSourceConfigurationV2 = `
{
	"kind": "GraphQL",
	"name": "countries",
	"internal": true,
	"root_fields": [
		{ "type": "Query", "fields": ["countries"] }
	],
	"config": {
		"url": "` + testGraphQLDataSource + `",
		"method": "POST"
	}
}`

const testGraphQLDataSourceConfiguration = `
{
  "type_name": "Query",
  "field_name": "countries",
  "mapping": {
	"disabled": false,
	"path": "countries"
  },
  "data_source": {
	"kind": "GraphQLDataSource",
	"data_source_config": {
	  "url": "` + testGraphQLDataSource + `",
	  "method": "POST"
	}
  }
}
`

const testRESTHeadersDataSourceConfigurationV2 = `
{
	"kind": "REST",
	"name": "headers",
	"internal": true,
	"root_fields": [
		{ "type": "Query", "fields": ["headers"] }
	],
	"config": {
		"url": "` + testRESTHeadersDataSource + `",
		"method": "GET",
		"headers": {
			"static": "barbaz",
			"injected": "{{ .request.header.injected }}"
		},
		"query": [],
		"body": ""
	}
}`

const testRESTDataSourceConfigurationV2 = `
{
	"kind": "REST",
	"name": "people",
	"internal": true,
	"root_fields": [
		{ "type": "Query", "fields": ["people"] }
	],
	"config": {
		"url": "` + testRESTDataSource + `",
		"method": "GET",
		"headers": {},
		"query": [],
		"body": ""
	}
}`

const testRESTDataSourceConfiguration = `
{
 "type_name": "Query",
 "field_name": "people",
  "mapping": {
	"disabled": false,
	"path": ""
  },
  "data_source": {
    "kind": "HTTPJSONDataSource",
	"data_source_config": {
	  "url": "` + testRESTDataSource + `",
	  "method": "GET",
	  "body": "",
	  "headers": [],
	  "default_type_name": "People",
	  "status_code_type_name_mappings": [
		{
		  "status_code": 200,
		  "type_name": ""
		}
	  ]
	}
  }
}`

func generateRESTDataSourceV2(gen func(dataSource *apidef.GraphQLEngineDataSource, restConf *apidef.GraphQLEngineDataSourceConfigREST)) apidef.GraphQLEngineDataSource {
	ds := apidef.GraphQLEngineDataSource{}
	if err := json.Unmarshal([]byte(testRESTDataSourceConfigurationV2), &ds); err != nil {
		panic(err)
	}

	restConf := apidef.GraphQLEngineDataSourceConfigREST{}
	if err := json.Unmarshal(ds.Config, &restConf); err != nil {
		panic(err)
	}

	gen(&ds, &restConf)

	rawConfig, err := json.Marshal(restConf)
	if err != nil {
		panic(err)
	}

	ds.Config = rawConfig
	return ds
}

func generateGraphQLDataSourceV2(gen func(dataSource *apidef.GraphQLEngineDataSource, graphqlConf *apidef.GraphQLEngineDataSourceConfigGraphQL)) apidef.GraphQLEngineDataSource {
	ds := apidef.GraphQLEngineDataSource{}
	if err := json.Unmarshal([]byte(testGraphQLDataSourceConfigurationV2), &ds); err != nil {
		panic(err)
	}

	graphqlConf := apidef.GraphQLEngineDataSourceConfigGraphQL{}
	if err := json.Unmarshal(ds.Config, &graphqlConf); err != nil {
		panic(err)
	}

	gen(&ds, &graphqlConf)

	rawConfig, err := json.Marshal(graphqlConf)
	if err != nil {
		panic(err)
	}

	ds.Config = rawConfig
	return ds
}

func generateRESTDataSource(gen ...func(restDataSource *datasource.HttpJsonDataSourceConfig)) json.RawMessage {
	typeFieldConfiguration := datasource.TypeFieldConfiguration{}
	if err := json.Unmarshal([]byte(testRESTDataSourceConfiguration), &typeFieldConfiguration); err != nil {
		panic(err)
	}

	restDataSource := datasource.HttpJsonDataSourceConfig{}
	_ = json.Unmarshal(typeFieldConfiguration.DataSource.Config, &restDataSource)

	if len(gen) > 0 {
		gen[0](&restDataSource)
	}

	rawData, _ := json.Marshal(restDataSource)

	return rawData
}

func generateGraphQLDataSource(gen ...func(graphQLDataSource *datasource.GraphQLDataSourceConfig)) json.RawMessage {
	typeFieldConfiguration := datasource.TypeFieldConfiguration{}
	if err := json.Unmarshal([]byte(testGraphQLDataSourceConfiguration), &typeFieldConfiguration); err != nil {
		panic(err)
	}

	graphQLDataSource := datasource.GraphQLDataSourceConfig{}
	_ = json.Unmarshal(typeFieldConfiguration.DataSource.Config, &graphQLDataSource)

	if len(gen) > 0 {
		gen[0](&graphQLDataSource)
	}

	rawData, _ := json.Marshal(graphQLDataSource)

	return rawData
}

func UpdateAPIVersion(spec *APISpec, name string, verGen func(version *apidef.VersionInfo)) {
	version := spec.VersionData.Versions[name]
	verGen(&version)
	spec.VersionData.Versions[name] = version
}

func jsonMarshalString(i interface{}) (out string) {
	b, _ := json.Marshal(i)
	return string(b)
}

func BuildAPI(apiGens ...func(spec *APISpec)) (specs []*APISpec) {
	if len(apiGens) == 0 {
		apiGens = append(apiGens, func(spec *APISpec) {})
	}

	for _, gen := range apiGens {
		spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
		if err := json.Unmarshal([]byte(sampleAPI), spec.APIDefinition); err != nil {
			panic(err)
		}

		gen(spec)
		specs = append(specs, spec)
	}

	return specs
}

func LoadAPI(specs ...*APISpec) (out []*APISpec) {
	globalConf := config.Global()
	oldPath := globalConf.AppPath
	globalConf.AppPath, _ = ioutil.TempDir("", "apps")
	config.SetGlobal(globalConf)
	defer func() {
		globalConf := config.Global()
		os.RemoveAll(globalConf.AppPath)
		globalConf.AppPath = oldPath
		config.SetGlobal(globalConf)
	}()

	for i, spec := range specs {
		specBytes, err := json.Marshal(spec)
		if err != nil {
			panic(err)
		}
		specFilePath := filepath.Join(config.Global().AppPath, spec.APIID+strconv.Itoa(i)+".json")
		if err := ioutil.WriteFile(specFilePath, specBytes, 0644); err != nil {
			panic(err)
		}
	}

	DoReload()

	for _, spec := range specs {
		out = append(out, getApiSpec(spec.APIID))
	}

	return out
}

func BuildAndLoadAPI(apiGens ...func(spec *APISpec)) (specs []*APISpec) {
	return LoadAPI(BuildAPI(apiGens...)...)
}

func CloneAPI(a *APISpec) *APISpec {
	new := &APISpec{}
	new.APIDefinition = &apidef.APIDefinition{}
	*new.APIDefinition = *a.APIDefinition

	return new
}

// Taken from https://medium.com/@mlowicki/http-s-proxy-in-golang-in-less-than-100-lines-of-code-6a51c2f2c38c
type httpProxyHandler struct {
	proto    string
	URL      string
	server   *http.Server
	listener net.Listener
}

func (p *httpProxyHandler) handleTunneling(w http.ResponseWriter, r *http.Request) {
	dest_conn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	client_conn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	go p.transfer(dest_conn, client_conn)
	go p.transfer(client_conn, dest_conn)
}

func (p *httpProxyHandler) transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}
func (p *httpProxyHandler) handleHTTP(w http.ResponseWriter, req *http.Request) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	p.copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (p *httpProxyHandler) Stop() error {
	ResetTestConfig()
	return p.server.Close()
}

func (p *httpProxyHandler) copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func initProxy(proto string, tlsConfig *tls.Config) *httpProxyHandler {
	proxy := &httpProxyHandler{proto: proto}

	proxy.server = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				proxy.handleTunneling(w, r)
			} else {
				proxy.handleHTTP(w, r)
			}
		}),
		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	var err error

	switch proto {
	case "http":
		proxy.listener, err = net.Listen("tcp", ":0")
	case "https":
		proxy.listener, err = tls.Listen("tcp", ":0", tlsConfig)
	default:
		log.Fatal("Unsupported proto scheme", proto)
	}

	if err != nil {
		log.Fatal(err)
	}

	proxy.URL = proto + "://" + proxy.listener.Addr().String()

	go proxy.server.Serve(proxy.listener)

	return proxy
}

func GenerateTestBinaryData() (buf *bytes.Buffer) {
	buf = new(bytes.Buffer)
	type testData struct {
		a float32
		b float64
		c uint32
	}
	for i := 0; i < 10; i++ {
		s := &testData{rand.Float32(), rand.Float64(), rand.Uint32()}
		binary.Write(buf, binary.BigEndian, s)
	}
	return buf
}

// openssl genrsa -out app.rsa
const jwtRSAPrivKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAyqZ4rwKF8qCExS7kpY4cnJa/37FMkJNkalZ3OuslLB0oRL8T
4c94kdF4aeNzSFkSe2n99IBI6Ssl79vbfMZb+t06L0Q94k+/P37x7+/RJZiff4y1
VGjrnrnMI2iu9l4iBBRYzNmG6eblroEMMWlgk5tysHgxB59CSNIcD9gqk1hx4n/F
gOmvKsfQgWHNlPSDTRcWGWGhB2/XgNVYG2pOlQxAPqLhBHeqGTXBbPfGF9cHzixp
sPr6GtbzPwhsQ/8bPxoJ7hdfn+rzztks3d6+HWURcyNTLRe0mjXjjee9Z6+gZ+H+
fS4pnP9tqT7IgU6ePUWTpjoiPtLexgsAa/ctjQIDAQABAoIBAECWvnBJRZgHQUn3
oDiECup9wbnyMI0D7UVXObk1qSteP69pl1SpY6xWLyLQs7WjbhiXt7FuEc7/SaAh
Wttx/W7/g8P85Bx1fmcmdsYakXaCJpPorQKyTibQ4ReIDfvIFN9n/MWNr0ptpVbx
GonFJFrneK52IGplgCLllLwYEbnULYcJc6E25Ro8U2gQjF2r43PDa07YiDrmB/GV
QQW4HTo+CA9rdK0bP8GpXgc0wpmBhx/t/YdnDg6qhzyUMk9As7JrAzYPjHO0cRun
vhA/aG/mdMmRumY75nj7wB5U5DgstsN2ER75Pjr1xe1knftIyNm15AShCPfLaLGo
dA2IpwECgYEA5E8h6ssa7QroCGwp/N0wSJW41hFYGygbOEg6yPWTJkqmMZVduD8X
/KFqJK4LcIbFQuR28+hWJpHm/RF1AMRhbbWkAj6h02gv5izFwDiFKev5paky4Evg
G8WfUOmSZ1D+fVxwaoG0OaRZpCovUTxYig3xrI659DMeKqpQ7e8l9ekCgYEA4zql
l4P4Dn0ydr+TI/s4NHIQHkaLQAVk3OWwyKowijXd8LCtuZRA1NKSpqQ4ZXi0B17o
9zzF5jEUjws3qWv4PKWdxJu3y+h/etsg7wxUeNizbY2ooUGeMbk0tWxJihbgaI7E
XxLIT50F3Ky4EJ2cUL9GmJ+gLCw0KIaVbkiyYAUCgYEA0WyVHB76r/2VIkS1rzHm
HG7ageKfAyoi7dmzsqsxM6q+EDWHJn8Zra8TAlp0O+AkClwvkUTJ4c9sJy9gODfr
dwtrSnPRVW74oRbovo4Z+H5xHbi65mwzQsZggYP/u63cA3pL1Cbt/wH3CFN52/aS
8PAhg7vYb1yEi3Z3jgoUtCECgYEAhSPX4u9waQzyhKG7lVmdlR1AVH0BGoIOl1/+
NZWC23i0klLzd8lmM00uoHWYldwjoC38UuFJE5eudCIeeybITMC9sHWNO+z+xP2g
TnDrDePrPkXCiLnp9ziNqb/JVyAQXTNJ3Gsk84EN7j9Fmna/IJDyzHq7XyaHaTdy
VyxBWAECgYEA4jYS07bPx5UMhKiMJDqUmDfLNFD97XwPoJIkOdn6ezqeOSmlmo7t
jxHLbCmsDOAsCU/0BlLXg9wMU7n5QKSlfTVGok/PU0rq2FUXQwyKGnellrqODwFQ
YGivtXBGXk1hlVYlje1RB+W6RQuDAegI5h8vl8pYJS9JQH0wjatsDaE=
-----END RSA PRIVATE KEY-----
`

const jwtECDSAPrivateKey = `-----BEGIN PRIVATE KEY-----
MHcCAQEEIFjaz7TJpBOHmQttPypGRh3rqaXvRpsWE/EWUiLzc6veoAoGCCqGSM49
AwEHoUQDQgAEDmKdIVHH9D5xkUiMJvo4T9H8yU+QYOIBlX5DYpJFtEvzTs4SsXYC
tFsPk7c31tOpMuS8aQiLsXR82VMLqQBf1w==
-----END PRIVATE KEY-----`

const jwtECDSAPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDmKdIVHH9D5xkUiMJvo4T9H8yU+Q
YOIBlX5DYpJFtEvzTs4SsXYCtFsPk7c31tOpMuS8aQiLsXR82VMLqQBf1w==
-----END PUBLIC KEY-----`

const jwtSecret = "9879879878787878"
const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randStringBytes(n int) string {
	b := make([]byte, n)

	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}

	return string(b)
}

package gateway

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"time"

	sprig "gopkg.in/Masterminds/sprig.v2"

	"github.com/TykTechnologies/tyk/headers"
	"github.com/TykTechnologies/tyk/rpc"

	circuit "github.com/rubyist/circuitbreaker"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/gojsonschema"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/regexp"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/garyburd/redigo/redis"
)

//const used by cache middleware
const SAFE_METHODS = "SAFE_METHODS"

const (
	LDAPStorageEngine apidef.StorageEngineCode = "ldap"
	RPCStorageEngine  apidef.StorageEngineCode = "rpc"
)

// Constants used by the version check middleware
const (
	headerLocation    = "header"
	urlParamLocation  = "url-param"
	urlLocation       = "url"
	expiredTimeFormat = "2006-01-02 15:04"
)

// URLStatus is a custom enum type to avoid collisions
type URLStatus int

// Enums representing the various statuses for a VersionInfo Path match during a
// proxy request
const (
	_ URLStatus = iota
	Ignored
	WhiteList
	BlackList
	Cached
	Transformed
	TransformedJQ
	HeaderInjected
	HeaderInjectedResponse
	TransformedResponse
	TransformedJQResponse
	HardTimeout
	CircuitBreaker
	URLRewrite
	VirtualPath
	RequestSizeLimit
	MethodTransformed
	RequestTracked
	RequestNotTracked
	ValidateJSONRequest
	Internal
)

// RequestStatus is a custom type to avoid collisions
type RequestStatus string

// Statuses of the request, all are false-y except StatusOk and StatusOkAndIgnore
const (
	VersionNotFound                RequestStatus = "Version information not found"
	VersionDoesNotExist            RequestStatus = "This API version does not seem to exist"
	VersionWhiteListStatusNotFound RequestStatus = "WhiteListStatus for path not found"
	VersionExpired                 RequestStatus = "Api Version has expired, please check documentation or contact administrator"
	EndPointNotAllowed             RequestStatus = "Requested endpoint is forbidden"
	StatusOkAndIgnore              RequestStatus = "Everything OK, passing and not filtering"
	StatusOk                       RequestStatus = "Everything OK, passing"
	StatusCached                   RequestStatus = "Cached path"
	StatusTransform                RequestStatus = "Transformed path"
	StatusTransformResponse        RequestStatus = "Transformed response"
	StatusTransformJQ              RequestStatus = "Transformed path with JQ"
	StatusTransformJQResponse      RequestStatus = "Transformed response with JQ"
	StatusHeaderInjected           RequestStatus = "Header injected"
	StatusMethodTransformed        RequestStatus = "Method Transformed"
	StatusHeaderInjectedResponse   RequestStatus = "Header injected on response"
	StatusRedirectFlowByReply      RequestStatus = "Exceptional action requested, redirecting flow!"
	StatusHardTimeout              RequestStatus = "Hard Timeout enforced on path"
	StatusCircuitBreaker           RequestStatus = "Circuit breaker enforced"
	StatusURLRewrite               RequestStatus = "URL Rewritten"
	StatusVirtualPath              RequestStatus = "Virtual Endpoint"
	StatusRequestSizeControlled    RequestStatus = "Request Size Limited"
	StatusRequestTracked           RequestStatus = "Request Tracked"
	StatusRequestNotTracked        RequestStatus = "Request Not Tracked"
	StatusValidateJSON             RequestStatus = "Validate JSON"
	StatusInternal                 RequestStatus = "Internal path"
)

// URLSpec represents a flattened specification for URLs, used to check if a proxy URL
// path is on any of the white, black or ignored lists. This is generated as part of the
// configuration init
type URLSpec struct {
	Spec                      *regexp.Regexp
	Status                    URLStatus
	MethodActions             map[string]apidef.EndpointMethodMeta
	CacheConfig               EndPointCacheMeta
	TransformAction           TransformSpec
	TransformResponseAction   TransformSpec
	TransformJQAction         TransformJQSpec
	TransformJQResponseAction TransformJQSpec
	InjectHeaders             apidef.HeaderInjectionMeta
	InjectHeadersResponse     apidef.HeaderInjectionMeta
	HardTimeout               apidef.HardTimeoutMeta
	CircuitBreaker            ExtendedCircuitBreakerMeta
	URLRewrite                *apidef.URLRewriteMeta
	VirtualPathSpec           apidef.VirtualMeta
	RequestSize               apidef.RequestSizeMeta
	MethodTransform           apidef.MethodTransformMeta
	TrackEndpoint             apidef.TrackEndpointMeta
	DoNotTrackEndpoint        apidef.TrackEndpointMeta
	ValidatePathMeta          apidef.ValidatePathMeta
	Internal                  apidef.InternalMeta
}

type EndPointCacheMeta struct {
	Method        string
	CacheKeyRegex string
}

type TransformSpec struct {
	apidef.TemplateMeta
	Template *template.Template
}

type ExtendedCircuitBreakerMeta struct {
	apidef.CircuitBreakerMeta
	CB *circuit.Breaker `json:"-"`
}

// APISpec represents a path specification for an API, to avoid enumerating multiple nested lists, a single
// flattened URL list is checked for matching paths and then it's status evaluated if found.
type APISpec struct {
	*apidef.APIDefinition
	sync.RWMutex

	RxPaths                  map[string][]URLSpec
	WhiteListEnabled         map[string]bool
	target                   *url.URL
	AuthManager              AuthorisationHandler
	SessionManager           SessionHandler
	OAuthManager             *OAuthManager
	OrgSessionManager        SessionHandler
	EventPaths               map[apidef.TykEvent][]config.TykEventHandler
	Health                   HealthChecker
	JSVM                     JSVM
	ResponseChain            []TykResponseHandler
	RoundRobin               RoundRobin
	URLRewriteEnabled        bool
	CircuitBreakerEnabled    bool
	EnforcedTimeoutEnabled   bool
	LastGoodHostList         *apidef.HostList
	HasRun                   bool
	ServiceRefreshInProgress bool
	HTTPTransport            http.RoundTripper
	HTTPTransportCreated     time.Time
	WSTransport              http.RoundTripper
	WSTransportCreated       time.Time
	GlobalConfig             config.Config
	OrgHasNoSession          bool

	middlewareChain http.Handler

	shouldRelease bool
}

// Release re;leases all resources associated with API spec
func (s *APISpec) Release() {
	// mark spec as to be released
	s.shouldRelease = true

	// release circuit breaker resources
	for _, path := range s.RxPaths {
		for _, urlSpec := range path {
			if urlSpec.CircuitBreaker.CB != nil {
				// this will force CB-event reading routing to exit
				urlSpec.CircuitBreaker.CB.Reset()

				// TODO: close all circuit breaker's event receivers
				// which should let event reading Go-routines to exit (need to change circuitbreaker package)
			}
		}
	}

	// release all other resources associated with spec
}

// APIDefinitionLoader will load an Api definition from a storage
// system.
type APIDefinitionLoader struct{}

// Nonce to use when interacting with the dashboard service
var ServiceNonce string

// MakeSpec will generate a flattened URLSpec from and APIDefinitions' VersionInfo data. paths are
// keyed to the Api version name, which is determined during routing to speed up lookups
func (a APIDefinitionLoader) MakeSpec(def *apidef.APIDefinition, logger *logrus.Entry) *APISpec {
	spec := &APISpec{}

	if logger == nil {
		logger = logrus.NewEntry(log)
	}

	// parse version expiration time stamps
	for key, ver := range def.VersionData.Versions {
		if ver.Expires == "" || ver.Expires == "-1" {
			continue
		}
		// calculate the time
		if t, err := time.Parse(expiredTimeFormat, ver.Expires); err != nil {
			logger.WithError(err).WithField("Expires", ver.Expires).Error("Could not parse expiry date for API")
		} else {
			ver.ExpiresTs = t
			def.VersionData.Versions[key] = ver
		}
	}

	spec.APIDefinition = def

	// We'll push the default HealthChecker:
	spec.Health = &DefaultHealthChecker{
		APIID: spec.APIID,
	}

	// Add any new session managers or auth handlers here
	spec.AuthManager = &DefaultAuthorisationManager{}

	spec.SessionManager = &DefaultSessionManager{}
	spec.OrgSessionManager = &DefaultSessionManager{}

	spec.GlobalConfig = config.Global()

	// Create and init the virtual Machine
	if config.Global().EnableJSVM {
		spec.JSVM.Init(spec, logger)
	}

	// Set up Event Handlers
	if len(def.EventHandlers.Events) > 0 {
		logger.Debug("Initializing event handlers")
	}
	spec.EventPaths = make(map[apidef.TykEvent][]config.TykEventHandler)
	for eventName, eventHandlerConfs := range def.EventHandlers.Events {
		logger.Debug("FOUND EVENTS TO INIT")
		for _, handlerConf := range eventHandlerConfs {
			logger.Debug("CREATING EVENT HANDLERS")
			eventHandlerInstance, err := EventHandlerByName(handlerConf, spec)

			if err != nil {
				logger.Error("Failed to init event handler: ", err)
			} else {
				logger.Debug("Init Event Handler: ", eventName)
				spec.EventPaths[eventName] = append(spec.EventPaths[eventName], eventHandlerInstance)
			}

		}
	}

	spec.RxPaths = make(map[string][]URLSpec, len(def.VersionData.Versions))
	spec.WhiteListEnabled = make(map[string]bool, len(def.VersionData.Versions))
	for _, v := range def.VersionData.Versions {
		var pathSpecs []URLSpec
		var whiteListSpecs bool

		// If we have transitioned to extended path specifications, we should use these now
		if v.UseExtendedPaths {
			pathSpecs, whiteListSpecs = a.getExtendedPathSpecs(v, spec)
		} else {
			logger.Warning("Legacy path detected! Upgrade to extended.")
			pathSpecs, whiteListSpecs = a.getPathSpecs(v)
		}
		spec.RxPaths[v.Name] = pathSpecs
		spec.WhiteListEnabled[v.Name] = whiteListSpecs
	}

	return spec
}

// FromDashboardService will connect and download ApiDefintions from a Tyk Dashboard instance.
func (a APIDefinitionLoader) FromDashboardService(endpoint, secret string) ([]*APISpec, error) {
	// Get the definitions
	log.Debug("Calling: ", endpoint)
	newRequest, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		log.Error("Failed to create request: ", err)
	}

	newRequest.Header.Set("authorization", secret)
	log.Debug("Using: NodeID: ", getNodeID())
	newRequest.Header.Set(headers.XTykNodeID, getNodeID())

	newRequest.Header.Set(headers.XTykNonce, ServiceNonce)

	c := initialiseClient(120 * time.Second)
	resp, err := c.Do(newRequest)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		body, _ := ioutil.ReadAll(resp.Body)
		reLogin()
		return nil, fmt.Errorf("login failure, Response was: %v", string(body))
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		reLogin()
		return nil, fmt.Errorf("dashboard API error, response was: %v", string(body))
	}

	// Extract tagged APIs#
	var list struct {
		Message []struct {
			ApiDefinition *apidef.APIDefinition `bson:"api_definition" json:"api_definition"`
		}
		Nonce string
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to decode body: %v body was: %v", err, string(body))
	}

	// Extract tagged entries only
	apiDefs := make([]*apidef.APIDefinition, 0)

	if config.Global().DBAppConfOptions.NodeIsSegmented {
		tagList := make(map[string]bool, len(config.Global().DBAppConfOptions.Tags))
		toLoad := make(map[string]*apidef.APIDefinition)

		for _, mt := range config.Global().DBAppConfOptions.Tags {
			tagList[mt] = true
		}

		for _, apiEntry := range list.Message {
			for _, t := range apiEntry.ApiDefinition.Tags {
				if tagList[t] {
					toLoad[apiEntry.ApiDefinition.APIID] = apiEntry.ApiDefinition
				}
			}
		}

		for _, apiDef := range toLoad {
			apiDefs = append(apiDefs, apiDef)
		}
	} else {
		for _, apiEntry := range list.Message {
			apiDefs = append(apiDefs, apiEntry.ApiDefinition)
		}
	}

	// Process
	var specs []*APISpec
	for _, def := range apiDefs {
		spec := a.MakeSpec(def, nil)
		specs = append(specs, spec)
	}

	// Set the nonce
	ServiceNonce = list.Nonce
	log.Debug("Loading APIS Finished: Nonce Set: ", ServiceNonce)

	return specs, nil
}

// FromCloud will connect and download ApiDefintions from a Mongo DB instance.
func (a APIDefinitionLoader) FromRPC(orgId string) ([]*APISpec, error) {
	if rpc.IsEmergencyMode() {
		return LoadDefinitionsFromRPCBackup()
	}

	store := RPCStorageHandler{}
	if !store.Connect() {
		return nil, errors.New("Can't connect RPC layer")
	}

	// enable segments
	var tags []string
	if config.Global().DBAppConfOptions.NodeIsSegmented {
		log.Info("Segmented node, loading: ", config.Global().DBAppConfOptions.Tags)
		tags = config.Global().DBAppConfOptions.Tags
	}

	apiCollection := store.GetApiDefinitions(orgId, tags)

	//store.Disconnect()

	if rpc.LoadCount() > 0 {
		if err := saveRPCDefinitionsBackup(apiCollection); err != nil {
			return nil, err
		}
	}

	return a.processRPCDefinitions(apiCollection)
}

// FromCloud will connect and download ApiDefintions from a Mongo DB instance.
func (a APIDefinitionLoader) FromRedis(db config.RedisDBAppConfOptionsConfig) ([]*APISpec, error) {
	var specs []*APISpec
	c := RedisPool.Get()
	defer c.Close()
	log.Info("Loading API Specification from redis")

	// Load API Definition from Redis DB
	apiKeys, err := redis.Strings(c.Do("KEYS", "*"))
	if err != nil {
		log.Error("Couldn't get api definition from redis db: ", err)
	}
	for _, v := range apiKeys {
		//Skip loading JWT-KEY keys
		if !strings.HasPrefix(v, "JWT-KEY-") {
			apiDefinition, _ := redis.String(c.Do("GET", v))
			def := a.ParseDefinition(strings.NewReader(apiDefinition))
			spec := a.MakeSpec(def, nil)
			specs = append(specs, spec)
		}
	}
	return specs, nil
}

func (a APIDefinitionLoader) processRPCDefinitions(apiCollection string) ([]*APISpec, error) {

	var apiDefs []*apidef.APIDefinition
	if err := json.Unmarshal([]byte(apiCollection), &apiDefs); err != nil {
		return nil, err
	}

	var specs []*APISpec
	for _, def := range apiDefs {
		def.DecodeFromDB()

		if config.Global().SlaveOptions.BindToSlugsInsteadOfListenPaths {
			newListenPath := "/" + def.Slug //+ "/"
			log.Warning("Binding to ",
				newListenPath,
				" instead of ",
				def.Proxy.ListenPath)

			def.Proxy.ListenPath = newListenPath
		}

		spec := a.MakeSpec(def, nil)
		specs = append(specs, spec)
	}

	return specs, nil
}

func (a APIDefinitionLoader) ParseDefinition(r io.Reader) *apidef.APIDefinition {
	def := &apidef.APIDefinition{}
	if err := json.NewDecoder(r).Decode(def); err != nil {
		log.Error("[RPC] --> Couldn't unmarshal api configuration: ", err)
	}
	return def
}

// FromDir will load APIDefinitions from a directory on the filesystem. Definitions need
// to be the JSON representation of APIDefinition object
func (a APIDefinitionLoader) FromDir(dir string) []*APISpec {
	var specs []*APISpec
	// Grab json files from directory
	paths, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	for _, path := range paths {
		log.Info("Loading API Specification from ", path)
		f, err := os.Open(path)
		if err != nil {
			log.Error("Couldn't open api configuration file: ", err)
			continue
		}
		def := a.ParseDefinition(f)
		f.Close()
		spec := a.MakeSpec(def, nil)
		specs = append(specs, spec)
	}
	return specs
}

func (a APIDefinitionLoader) getPathSpecs(apiVersionDef apidef.VersionInfo) ([]URLSpec, bool) {
	ignoredPaths := a.compilePathSpec(apiVersionDef.Paths.Ignored, Ignored)
	blackListPaths := a.compilePathSpec(apiVersionDef.Paths.BlackList, BlackList)
	whiteListPaths := a.compilePathSpec(apiVersionDef.Paths.WhiteList, WhiteList)

	combinedPath := []URLSpec{}
	combinedPath = append(combinedPath, ignoredPaths...)
	combinedPath = append(combinedPath, blackListPaths...)
	combinedPath = append(combinedPath, whiteListPaths...)

	return combinedPath, len(whiteListPaths) > 0
}

func (a APIDefinitionLoader) generateRegex(stringSpec string, newSpec *URLSpec, specType URLStatus) {
	apiLangIDsRegex := regexp.MustCompile(`{([^}]*)}`)
	asRegexStr := apiLangIDsRegex.ReplaceAllString(stringSpec, `([^/]*)`)
	asRegex, _ := regexp.Compile(asRegexStr)
	newSpec.Status = specType
	newSpec.Spec = asRegex
}

func (a APIDefinitionLoader) compilePathSpec(paths []string, specType URLStatus) []URLSpec {
	// transform a configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	urlSpec := []URLSpec{}

	for _, stringSpec := range paths {
		newSpec := URLSpec{}
		a.generateRegex(stringSpec, &newSpec, specType)
		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) compileExtendedPathSpec(paths []apidef.EndPointMeta, specType URLStatus) []URLSpec {
	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	urlSpec := []URLSpec{}

	for _, stringSpec := range paths {
		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, specType)

		// Extend with method actions
		newSpec.MethodActions = stringSpec.MethodActions
		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) compileCachedPathSpec(oldpaths []string, newpaths []apidef.CacheMeta) []URLSpec {
	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	urlSpec := []URLSpec{}

	for _, stringSpec := range oldpaths {
		newSpec := URLSpec{}
		a.generateRegex(stringSpec, &newSpec, Cached)
		newSpec.CacheConfig.Method = SAFE_METHODS
		newSpec.CacheConfig.CacheKeyRegex = ""
		// Extend with method actions
		urlSpec = append(urlSpec, newSpec)
	}

	for _, spec := range newpaths {
		newSpec := URLSpec{}
		a.generateRegex(spec.Path, &newSpec, Cached)
		newSpec.CacheConfig.Method = spec.Method
		newSpec.CacheConfig.CacheKeyRegex = spec.CacheKeyRegex
		// Extend with method actions
		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) filterSprigFuncs() template.FuncMap {
	tmp := sprig.GenericFuncMap()
	delete(tmp, "env")
	delete(tmp, "expandenv")

	return template.FuncMap(tmp)
}

func (a APIDefinitionLoader) loadFileTemplate(path string) (*template.Template, error) {
	log.Debug("-- Loading template: ", path)
	return apidef.Template.New("").Funcs(a.filterSprigFuncs()).ParseFiles(path)
}

func (a APIDefinitionLoader) loadBlobTemplate(blob string) (*template.Template, error) {
	log.Debug("-- Loading blob")
	uDec, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return nil, err
	}
	return apidef.Template.New("").Funcs(a.filterSprigFuncs()).Parse(string(uDec))
}

func (a APIDefinitionLoader) compileTransformPathSpec(paths []apidef.TemplateMeta, stat URLStatus) []URLSpec {
	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	urlSpec := []URLSpec{}

	log.Debug("Checking for transform paths...")
	for _, stringSpec := range paths {
		log.Debug("-- Generating path")
		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat)
		// Extend with template actions

		newTransformSpec := TransformSpec{TemplateMeta: stringSpec}

		// Load the templates
		var err error

		switch stringSpec.TemplateData.Mode {
		case apidef.UseFile:
			log.Debug("-- Using File mode")
			newTransformSpec.Template, err = a.loadFileTemplate(stringSpec.TemplateData.TemplateSource)
		case apidef.UseBlob:
			log.Debug("-- Blob mode")
			newTransformSpec.Template, err = a.loadBlobTemplate(stringSpec.TemplateData.TemplateSource)
		default:
			log.Warning("[Transform Templates] No template mode defined! Found: ", stringSpec.TemplateData.Mode)
			err = errors.New("No valid template mode defined, must be either 'file' or 'blob'")
		}

		if stat == Transformed {
			newSpec.TransformAction = newTransformSpec
		} else {
			newSpec.TransformResponseAction = newTransformSpec
		}

		if err == nil {
			urlSpec = append(urlSpec, newSpec)
			log.Debug("-- Loaded")
		} else {
			log.Error("Template load failure! Skipping transformation: ", err)
		}

	}

	return urlSpec
}

func (a APIDefinitionLoader) compileInjectedHeaderSpec(paths []apidef.HeaderInjectionMeta, stat URLStatus) []URLSpec {
	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	urlSpec := []URLSpec{}

	for _, stringSpec := range paths {
		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat)
		// Extend with method actions
		if stat == HeaderInjected {
			newSpec.InjectHeaders = stringSpec
		} else {
			newSpec.InjectHeadersResponse = stringSpec
		}

		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) compileMethodTransformSpec(paths []apidef.MethodTransformMeta, stat URLStatus) []URLSpec {
	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	urlSpec := []URLSpec{}

	for _, stringSpec := range paths {
		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat)
		newSpec.MethodTransform = stringSpec

		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) compileTimeoutPathSpec(paths []apidef.HardTimeoutMeta, stat URLStatus) []URLSpec {
	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	urlSpec := []URLSpec{}

	for _, stringSpec := range paths {
		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat)
		// Extend with method actions
		newSpec.HardTimeout = stringSpec

		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) compileRequestSizePathSpec(paths []apidef.RequestSizeMeta, stat URLStatus) []URLSpec {
	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	urlSpec := []URLSpec{}

	for _, stringSpec := range paths {
		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat)
		// Extend with method actions
		newSpec.RequestSize = stringSpec

		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) compileCircuitBreakerPathSpec(paths []apidef.CircuitBreakerMeta, stat URLStatus, apiSpec *APISpec) []URLSpec {
	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	urlSpec := []URLSpec{}

	for _, stringSpec := range paths {
		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat)
		// Extend with method actions
		newSpec.CircuitBreaker = ExtendedCircuitBreakerMeta{CircuitBreakerMeta: stringSpec}
		log.Debug("Initialising circuit breaker for: ", stringSpec.Path)
		newSpec.CircuitBreaker.CB = circuit.NewRateBreaker(stringSpec.ThresholdPercent, stringSpec.Samples)
		events := newSpec.CircuitBreaker.CB.Subscribe()
		go func(path string, spec *APISpec, breakerPtr *circuit.Breaker) {
			timerActive := false
			for e := range events {
				switch e {
				case circuit.BreakerTripped:
					log.Warning("[PROXY] [CIRCUIT BREAKER] Breaker tripped for path: ", path)
					log.Debug("Breaker tripped: ", e)
					// Start a timer function

					if !timerActive {
						go func(timeout int, breaker *circuit.Breaker) {
							log.Debug("-- Sleeping for (s): ", timeout)
							time.Sleep(time.Duration(timeout) * time.Second)
							log.Debug("-- Resetting breaker")
							breaker.Reset()
							timerActive = false
						}(newSpec.CircuitBreaker.ReturnToServiceAfter, breakerPtr)
						timerActive = true
					}

					if spec.Proxy.ServiceDiscovery.UseDiscoveryService {
						if ServiceCache != nil {
							log.Warning("[PROXY] [CIRCUIT BREAKER] Refreshing host list")
							ServiceCache.Delete(spec.APIID)
						}
					}

					spec.FireEvent(EventBreakerTriggered, EventCurcuitBreakerMeta{
						EventMetaDefault: EventMetaDefault{Message: "Breaker Tripped"},
						CircuitEvent:     e,
						Path:             path,
						APIID:            spec.APIID,
					})

				case circuit.BreakerReset:
					// check if this spec is set to release resources
					if spec.shouldRelease {
						// time to stop this Go-routine
						return
					}

					spec.FireEvent(EventBreakerTriggered, EventCurcuitBreakerMeta{
						EventMetaDefault: EventMetaDefault{Message: "Breaker Reset"},
						CircuitEvent:     e,
						Path:             path,
						APIID:            spec.APIID,
					})

				}
			}
		}(stringSpec.Path, apiSpec, newSpec.CircuitBreaker.CB)

		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) compileURLRewritesPathSpec(paths []apidef.URLRewriteMeta, stat URLStatus) []URLSpec {
	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	urlSpec := []URLSpec{}

	for _, stringSpec := range paths {
		curStringSpec := stringSpec
		newSpec := URLSpec{}
		a.generateRegex(curStringSpec.Path, &newSpec, stat)
		// Extend with method actions
		newSpec.URLRewrite = &curStringSpec

		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) compileVirtualPathspathSpec(paths []apidef.VirtualMeta, stat URLStatus, apiSpec *APISpec) []URLSpec {
	if !config.Global().EnableJSVM {
		return nil
	}

	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	urlSpec := []URLSpec{}
	for _, stringSpec := range paths {
		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat)
		// Extend with method actions
		newSpec.VirtualPathSpec = stringSpec

		preLoadVirtualMetaCode(&newSpec.VirtualPathSpec, &apiSpec.JSVM)

		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) compileTrackedEndpointPathspathSpec(paths []apidef.TrackEndpointMeta, stat URLStatus) []URLSpec {
	urlSpec := []URLSpec{}

	for _, stringSpec := range paths {
		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat)

		// set Path if it wasn't set
		if stringSpec.Path == "" {
			// even if it is empty (and regex matches everything) some middlewares expect to be value here
			stringSpec.Path = "/"
		}

		// Extend with method actions
		newSpec.TrackEndpoint = stringSpec
		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) compileValidateJSONPathspathSpec(paths []apidef.ValidatePathMeta, stat URLStatus) []URLSpec {
	urlSpec := make([]URLSpec, len(paths))

	for i, stringSpec := range paths {
		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat)
		// Extend with method actions

		stringSpec.SchemaCache = gojsonschema.NewGoLoader(stringSpec.Schema)
		newSpec.ValidatePathMeta = stringSpec
		urlSpec[i] = newSpec
	}

	return urlSpec
}

func (a APIDefinitionLoader) compileUnTrackedEndpointPathspathSpec(paths []apidef.TrackEndpointMeta, stat URLStatus) []URLSpec {
	urlSpec := []URLSpec{}

	for _, stringSpec := range paths {
		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat)
		// Extend with method actions
		newSpec.DoNotTrackEndpoint = stringSpec
		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) compileInternalPathspathSpec(paths []apidef.InternalMeta, stat URLStatus) []URLSpec {
	urlSpec := []URLSpec{}

	for _, stringSpec := range paths {
		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat)
		// Extend with method actions
		newSpec.Internal = stringSpec
		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) getExtendedPathSpecs(apiVersionDef apidef.VersionInfo, apiSpec *APISpec) ([]URLSpec, bool) {
	// TODO: New compiler here, needs to put data into a different structure

	ignoredPaths := a.compileExtendedPathSpec(apiVersionDef.ExtendedPaths.Ignored, Ignored)
	blackListPaths := a.compileExtendedPathSpec(apiVersionDef.ExtendedPaths.BlackList, BlackList)
	whiteListPaths := a.compileExtendedPathSpec(apiVersionDef.ExtendedPaths.WhiteList, WhiteList)
	cachedPaths := a.compileCachedPathSpec(apiVersionDef.ExtendedPaths.Cached, apiVersionDef.ExtendedPaths.AdvanceCacheConfig)
	transformPaths := a.compileTransformPathSpec(apiVersionDef.ExtendedPaths.Transform, Transformed)
	transformResponsePaths := a.compileTransformPathSpec(apiVersionDef.ExtendedPaths.TransformResponse, TransformedResponse)
	transformJQPaths := a.compileTransformJQPathSpec(apiVersionDef.ExtendedPaths.TransformJQ, TransformedJQ)
	transformJQResponsePaths := a.compileTransformJQPathSpec(apiVersionDef.ExtendedPaths.TransformJQResponse, TransformedJQResponse)
	headerTransformPaths := a.compileInjectedHeaderSpec(apiVersionDef.ExtendedPaths.TransformHeader, HeaderInjected)
	headerTransformPathsOnResponse := a.compileInjectedHeaderSpec(apiVersionDef.ExtendedPaths.TransformResponseHeader, HeaderInjectedResponse)
	hardTimeouts := a.compileTimeoutPathSpec(apiVersionDef.ExtendedPaths.HardTimeouts, HardTimeout)
	circuitBreakers := a.compileCircuitBreakerPathSpec(apiVersionDef.ExtendedPaths.CircuitBreaker, CircuitBreaker, apiSpec)
	urlRewrites := a.compileURLRewritesPathSpec(apiVersionDef.ExtendedPaths.URLRewrite, URLRewrite)
	virtualPaths := a.compileVirtualPathspathSpec(apiVersionDef.ExtendedPaths.Virtual, VirtualPath, apiSpec)
	requestSizes := a.compileRequestSizePathSpec(apiVersionDef.ExtendedPaths.SizeLimit, RequestSizeLimit)
	methodTransforms := a.compileMethodTransformSpec(apiVersionDef.ExtendedPaths.MethodTransforms, MethodTransformed)
	trackedPaths := a.compileTrackedEndpointPathspathSpec(apiVersionDef.ExtendedPaths.TrackEndpoints, RequestTracked)
	unTrackedPaths := a.compileUnTrackedEndpointPathspathSpec(apiVersionDef.ExtendedPaths.DoNotTrackEndpoints, RequestNotTracked)
	validateJSON := a.compileValidateJSONPathspathSpec(apiVersionDef.ExtendedPaths.ValidateJSON, ValidateJSONRequest)
	internalPaths := a.compileInternalPathspathSpec(apiVersionDef.ExtendedPaths.Internal, Internal)

	combinedPath := []URLSpec{}
	combinedPath = append(combinedPath, ignoredPaths...)
	combinedPath = append(combinedPath, blackListPaths...)
	combinedPath = append(combinedPath, whiteListPaths...)
	combinedPath = append(combinedPath, cachedPaths...)
	combinedPath = append(combinedPath, transformPaths...)
	combinedPath = append(combinedPath, transformResponsePaths...)
	combinedPath = append(combinedPath, transformJQPaths...)
	combinedPath = append(combinedPath, transformJQResponsePaths...)
	combinedPath = append(combinedPath, headerTransformPaths...)
	combinedPath = append(combinedPath, headerTransformPathsOnResponse...)
	combinedPath = append(combinedPath, hardTimeouts...)
	combinedPath = append(combinedPath, circuitBreakers...)
	combinedPath = append(combinedPath, urlRewrites...)
	combinedPath = append(combinedPath, requestSizes...)
	combinedPath = append(combinedPath, virtualPaths...)
	combinedPath = append(combinedPath, methodTransforms...)
	combinedPath = append(combinedPath, trackedPaths...)
	combinedPath = append(combinedPath, unTrackedPaths...)
	combinedPath = append(combinedPath, validateJSON...)
	combinedPath = append(combinedPath, internalPaths...)

	return combinedPath, len(whiteListPaths) > 0
}

func (a *APISpec) Init(authStore, sessionStore, healthStore, orgStore storage.Handler) {
	a.AuthManager.Init(authStore)
	a.SessionManager.Init(sessionStore)
	a.Health.Init(healthStore)
	a.OrgSessionManager.Init(orgStore)
}

func (a *APISpec) StopSessionManagerPool() {
	a.SessionManager.Stop()
	a.OrgSessionManager.Stop()
}

func (a *APISpec) getURLStatus(stat URLStatus) RequestStatus {
	switch stat {
	case Ignored:
		return StatusOkAndIgnore
	case BlackList:
		return EndPointNotAllowed
	case WhiteList:
		return StatusOk
	case Cached:
		return StatusCached
	case Transformed:
		return StatusTransform
	case TransformedJQ:
		return StatusTransformJQ
	case HeaderInjected:
		return StatusHeaderInjected
	case HeaderInjectedResponse:
		return StatusHeaderInjectedResponse
	case TransformedResponse:
		return StatusTransformResponse
	case TransformedJQResponse:
		return StatusTransformJQResponse
	case HardTimeout:
		return StatusHardTimeout
	case CircuitBreaker:
		return StatusCircuitBreaker
	case URLRewrite:
		return StatusURLRewrite
	case VirtualPath:
		return StatusVirtualPath
	case RequestSizeLimit:
		return StatusRequestSizeControlled
	case MethodTransformed:
		return StatusMethodTransformed
	case RequestTracked:
		return StatusRequestTracked
	case RequestNotTracked:
		return StatusRequestNotTracked
	case ValidateJSONRequest:
		return StatusValidateJSON
	case Internal:
		return StatusInternal

	default:
		log.Error("URL Status was not one of Ignored, Blacklist or WhiteList! Blocking.")
		return EndPointNotAllowed
	}
}

// URLAllowedAndIgnored checks if a url is allowed and ignored.
func (a *APISpec) URLAllowedAndIgnored(r *http.Request, rxPaths []URLSpec, whiteListStatus bool) (RequestStatus, interface{}) {
	// Check if ignored
	for _, v := range rxPaths {
		if !v.Spec.MatchString(r.URL.Path) {
			continue
		}

		if v.MethodActions != nil {
			// We are using an extended path set, check for the method
			methodMeta, matchMethodOk := v.MethodActions[r.Method]
			if !matchMethodOk {
				continue
			}

			// Matched the method, check what status it is
			// TODO: Extend here for additional reply options
			switch methodMeta.Action {
			case apidef.NoAction:
				// NoAction status means we're not treating this request in any special or exceptional way
				return a.getURLStatus(v.Status), nil
			case apidef.Reply:
				return StatusRedirectFlowByReply, &methodMeta
			default:
				log.Error("URL Method Action was not set to NoAction, blocking.")
				return EndPointNotAllowed, nil
			}
		}

		if r.Method == v.Internal.Method && v.Status == Internal && !ctxLoopingEnabled(r) {
			return EndPointNotAllowed, nil
		}

		if whiteListStatus {
			// We have a whitelist, nothing gets through unless specifically defined
			switch v.Status {
			case WhiteList, BlackList, Ignored:
			default:
				if v.Status == Internal && r.Method == v.Internal.Method && ctxLoopingEnabled(r) {
					return a.getURLStatus(v.Status), nil
				} else {
					return EndPointNotAllowed, nil
				}
			}
		}

		if v.TransformAction.Template != nil {
			return a.getURLStatus(v.Status), &v.TransformAction
		}

		if v.TransformJQAction.Filter != "" {
			return a.getURLStatus(v.Status), &v.TransformJQAction
		}

		// TODO: Fix, Not a great detection method
		if len(v.InjectHeaders.Path) > 0 {
			return a.getURLStatus(v.Status), &v.InjectHeaders
		}

		// Using a legacy path, handle it raw.
		return a.getURLStatus(v.Status), nil
	}

	// Nothing matched - should we still let it through?
	if whiteListStatus {
		// We have a whitelist, nothing gets through unless specifically defined
		return EndPointNotAllowed, nil
	}

	// No whitelist, but also not in any of the other lists, let it through and filter
	return StatusOk, nil
}

// CheckSpecMatchesStatus checks if a url spec has a specific status
func (a *APISpec) CheckSpecMatchesStatus(r *http.Request, rxPaths []URLSpec, mode URLStatus) (bool, interface{}) {
	var matchPath, method string

	//If url-rewrite middleware was used, call response middleware of original path and not of rewritten path
	// context variable UrlRewritePath is set by rewrite middleware
	if mode == TransformedJQResponse || mode == HeaderInjectedResponse || mode == TransformedResponse {
		matchPath = ctxGetUrlRewritePath(r)
		method = ctxGetRequestMethod(r)
		if matchPath == "" {
			matchPath = r.URL.Path
		}
	} else {
		matchPath = r.URL.Path
		method = r.Method
	}

	if a.Proxy.ListenPath != "/" {
		matchPath = strings.TrimPrefix(matchPath, a.Proxy.ListenPath)
	}

	if !strings.HasPrefix(matchPath, "/") {
		matchPath = "/" + matchPath
	}

	// Check if ignored
	for _, v := range rxPaths {
		if mode != v.Status {
			continue
		}
		if !v.Spec.MatchString(matchPath) {
			continue
		}

		switch v.Status {
		case Ignored, BlackList, WhiteList:
			return true, nil
		case Cached:
			if method == v.CacheConfig.Method || (v.CacheConfig.Method == SAFE_METHODS && (method == "GET" || method == "HEADERS" || method == "OPTIONS")) {
				return true, &v.CacheConfig
			}
		case Transformed:
			if method == v.TransformAction.Method {
				return true, &v.TransformAction
			}
		case TransformedJQ:
			if method == v.TransformJQAction.Method {
				return true, &v.TransformJQAction
			}
		case HeaderInjected:
			if method == v.InjectHeaders.Method {
				return true, &v.InjectHeaders
			}
		case HeaderInjectedResponse:
			if method == v.InjectHeadersResponse.Method {
				return true, &v.InjectHeadersResponse
			}
		case TransformedResponse:
			if method == v.TransformResponseAction.Method {
				return true, &v.TransformResponseAction
			}
		case TransformedJQResponse:
			if method == v.TransformJQResponseAction.Method {
				return true, &v.TransformJQResponseAction
			}
		case HardTimeout:
			if r.Method == v.HardTimeout.Method {
				return true, &v.HardTimeout.TimeOut
			}
		case CircuitBreaker:
			if method == v.CircuitBreaker.Method {
				return true, &v.CircuitBreaker
			}
		case URLRewrite:
			if method == v.URLRewrite.Method {
				return true, v.URLRewrite
			}
		case VirtualPath:
			if method == v.VirtualPathSpec.Method {
				return true, &v.VirtualPathSpec
			}
		case RequestSizeLimit:
			if method == v.RequestSize.Method {
				return true, &v.RequestSize
			}
		case MethodTransformed:
			if method == v.MethodTransform.Method {
				return true, &v.MethodTransform
			}
		case RequestTracked:
			if method == v.TrackEndpoint.Method {
				return true, &v.TrackEndpoint
			}
		case RequestNotTracked:
			if method == v.DoNotTrackEndpoint.Method {
				return true, &v.DoNotTrackEndpoint
			}
		case ValidateJSONRequest:
			if method == v.ValidatePathMeta.Method {
				return true, &v.ValidatePathMeta
			}
		case Internal:
			if method == v.Internal.Method {
				return true, &v.Internal
			}
		}
	}
	return false, nil
}

func (a *APISpec) getVersionFromRequest(r *http.Request) string {
	if a.VersionData.NotVersioned {
		return ""
	}

	switch a.VersionDefinition.Location {
	case headerLocation:
		return r.Header.Get(a.VersionDefinition.Key)

	case urlParamLocation:
		return r.URL.Query().Get(a.VersionDefinition.Key)

	case urlLocation:
		uPath := strings.TrimPrefix(r.URL.Path, a.Proxy.ListenPath)
		uPath = strings.TrimPrefix(uPath, "/"+a.Slug)

		// First non-empty part of the path is the version ID
		for _, part := range strings.Split(uPath, "/") {
			if part != "" {
				return part
			}
		}
	}
	return ""
}

// VersionExpired checks if an API version (during a proxied
// request) is expired. If it isn't and the configured time was valid,
// it also returns the expiration time.
func (a *APISpec) VersionExpired(versionDef *apidef.VersionInfo) (bool, *time.Time) {
	if a.VersionData.NotVersioned {
		return false, nil
	}

	// Never expires
	if versionDef.Expires == "" || versionDef.Expires == "-1" {
		return false, nil
	}

	// otherwise use parsed timestamp
	if versionDef.ExpiresTs.IsZero() {
		log.Error("Could not parse expiry date for API, disallow")
		return true, nil
	}

	// It's in the past, expire
	// It's in the future, keep going
	return time.Since(versionDef.ExpiresTs) >= 0, &versionDef.ExpiresTs
}

// RequestValid will check if an incoming request has valid version
// data and return a RequestStatus that describes the status of the
// request
func (a *APISpec) RequestValid(r *http.Request) (bool, RequestStatus, interface{}) {
	versionMetaData, versionPaths, whiteListStatus, vstat := a.Version(r)

	// Screwed up version info - fail and pass through
	if vstat != StatusOk {
		return false, vstat, nil
	}

	// Is the API version expired?
	// TODO: Don't abuse the interface{} return value for both
	// *apidef.EndpointMethodMeta and *time.Time. Probably need to
	// redesign or entirely remove RequestValid. See discussion on
	// https://github.com/TykTechnologies/tyk/pull/776
	expired, expTime := a.VersionExpired(versionMetaData)
	if expired {
		return false, VersionExpired, nil
	}

	// not expired, let's check path info
	status, meta := a.URLAllowedAndIgnored(r, versionPaths, whiteListStatus)
	switch status {
	case EndPointNotAllowed:
		return false, status, expTime
	case StatusRedirectFlowByReply:
		return true, status, meta
	case StatusOkAndIgnore, StatusCached, StatusTransform,
		StatusHeaderInjected, StatusMethodTransformed:
		return true, status, expTime
	default:
		return true, StatusOk, expTime
	}
}

// Version attempts to extract the version data from a request, depending on where it is stored in the
// request (currently only "header" is supported)
func (a *APISpec) Version(r *http.Request) (*apidef.VersionInfo, []URLSpec, bool, RequestStatus) {
	var version apidef.VersionInfo

	// try the context first
	if v := ctxGetVersionInfo(r); v != nil {
		version = *v
	} else {
		// Are we versioned?
		if a.VersionData.NotVersioned {
			// Get the first one in the list
			for _, v := range a.VersionData.Versions {
				version = v
				break
			}
		} else {
			// Extract Version Info
			// First checking for if default version is set
			vName := a.getVersionFromRequest(r)
			if vName == "" {
				if a.VersionData.DefaultVersion == "" {
					return &version, nil, false, VersionNotFound
				}
				vName = a.VersionData.DefaultVersion
				ctxSetDefaultVersion(r)
			}
			// Load Version Data - General
			var ok bool
			if version, ok = a.VersionData.Versions[vName]; !ok {
				return &version, nil, false, VersionDoesNotExist
			}
		}

		// cache for the future
		ctxSetVersionInfo(r, &version)
	}

	// Load path data and whitelist data for version
	rxPaths, rxOk := a.RxPaths[version.Name]
	if !rxOk {
		log.Error("no RX Paths found for version ", version.Name)
		return &version, nil, false, VersionDoesNotExist
	}

	whiteListStatus, wlOk := a.WhiteListEnabled[version.Name]
	if !wlOk {
		log.Error("No whitelist data found")
		return &version, nil, false, VersionWhiteListStatusNotFound
	}

	return &version, rxPaths, whiteListStatus, StatusOk
}

type RoundRobin struct {
	pos uint32
}

func (r *RoundRobin) WithLen(len int) int {
	if len < 1 {
		return 0
	}
	// -1 to start at 0, not 1
	cur := atomic.AddUint32(&r.pos, 1) - 1
	return int(cur) % len
}

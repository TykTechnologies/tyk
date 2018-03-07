package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"time"

	"github.com/rubyist/circuitbreaker"

	"github.com/TykTechnologies/gojsonschema"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
)

const (
	LDAPStorageEngine apidef.StorageEngineCode = "ldap"
	RPCStorageEngine  apidef.StorageEngineCode = "rpc"
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
	HeaderInjected
	HeaderInjectedResponse
	TransformedResponse
	HardTimeout
	CircuitBreaker
	URLRewrite
	VirtualPath
	RequestSizeLimit
	MethodTransformed
	RequestTracked
	RequestNotTracked
	ValidateJSONRequest
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
	StatusHeaderInjected           RequestStatus = "Header injected"
	StatusMethodTransformed        RequestStatus = "Method Transformed"
	StatusHeaderInjectedResponse   RequestStatus = "Header injected on response"
	StatusRedirectFlowByReply      RequestStatus = "Exceptional action requested, redirecting flow!"
	StatusHardTimeout              RequestStatus = "Hard Timeout enforced on path"
	StatusCircuitBreaker           RequestStatus = "Circuit breaker enforced"
	StatusURLRewrite               RequestStatus = "URL Rewritten"
	StatusVirtualPath              RequestStatus = "Virtual Endpoint"
	StatusRequestSizeControlled    RequestStatus = "Request Size Limited"
	StatusRequesTracked            RequestStatus = "Request Tracked"
	StatusRequestNotTracked        RequestStatus = "Request Not Tracked"
	StatusValidateJSON             RequestStatus = "Validate JSON"
)

// URLSpec represents a flattened specification for URLs, used to check if a proxy URL
// path is on any of the white, plack or ignored lists. This is generated as part of the
// configuration init
type URLSpec struct {
	Spec                    *regexp.Regexp
	Status                  URLStatus
	MethodActions           map[string]apidef.EndpointMethodMeta
	TransformAction         TransformSpec
	TransformResponseAction TransformSpec
	InjectHeaders           apidef.HeaderInjectionMeta
	InjectHeadersResponse   apidef.HeaderInjectionMeta
	HardTimeout             apidef.HardTimeoutMeta
	CircuitBreaker          ExtendedCircuitBreakerMeta
	URLRewrite              apidef.URLRewriteMeta
	VirtualPathSpec         apidef.VirtualMeta
	RequestSize             apidef.RequestSizeMeta
	MethodTransform         apidef.MethodTransformMeta
	TrackEndpoint           apidef.TrackEndpointMeta
	DoNotTrackEndpoint      apidef.TrackEndpointMeta
	ValidatePathMeta        apidef.ValidatePathMeta
}

type TransformSpec struct {
	apidef.TemplateMeta
	Template *template.Template
}

type ExtendedCircuitBreakerMeta struct {
	apidef.CircuitBreakerMeta
	CB *circuit.Breaker
}

// APISpec represents a path specification for an API, to avoid enumerating multiple nested lists, a single
// flattened URL list is checked for matching paths and then it's status evaluated if found.
type APISpec struct {
	*apidef.APIDefinition
	sync.Mutex

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
}

// APIDefinitionLoader will load an Api definition from a storage
// system.
type APIDefinitionLoader struct{}

// Nonce to use when interacting with the dashboard service
var ServiceNonce string

// MakeSpec will generate a flattened URLSpec from and APIDefinitions' VersionInfo data. paths are
// keyed to the Api version name, which is determined during routing to speed up lookups
func (a APIDefinitionLoader) MakeSpec(def *apidef.APIDefinition) *APISpec {
	spec := &APISpec{}
	spec.APIDefinition = def

	// We'll push the default HealthChecker:
	spec.Health = &DefaultHealthChecker{
		APIID: spec.APIID,
	}

	// Add any new session managers or auth handlers here
	spec.AuthManager = &DefaultAuthorisationManager{}

	spec.SessionManager = &DefaultSessionManager{}
	spec.OrgSessionManager = &DefaultSessionManager{}

	// Create and init the virtual Machine
	if config.Global.EnableJSVM {
		spec.JSVM.Init(spec)
	}

	// Set up Event Handlers
	log.Debug("INITIALISING EVENT HANDLERS")
	spec.EventPaths = make(map[apidef.TykEvent][]config.TykEventHandler)
	for eventName, eventHandlerConfs := range def.EventHandlers.Events {
		log.Debug("FOUND EVENTS TO INIT")
		for _, handlerConf := range eventHandlerConfs {
			log.Debug("CREATING EVENT HANDLERS")
			eventHandlerInstance, err := EventHandlerByName(handlerConf, spec)

			if err != nil {
				log.Error("Failed to init event handler: ", err)
			} else {
				log.Debug("Init Event Handler: ", eventName)
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
			log.Warning("Legacy path detected! Upgrade to extended.")
			pathSpecs, whiteListSpecs = a.getPathSpecs(v)
		}
		spec.RxPaths[v.Name] = pathSpecs
		spec.WhiteListEnabled[v.Name] = whiteListSpecs
	}

	return spec
}

// FromDashboardService will connect and download ApiDefintions from a Tyk Dashboard instance.
func (a APIDefinitionLoader) FromDashboardService(endpoint, secret string) []*APISpec {
	// Get the definitions
	log.Debug("Calling: ", endpoint)
	newRequest, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		log.Error("Failed to create request: ", err)
	}

	newRequest.Header.Set("authorization", secret)
	log.Debug("Using: NodeID: ", NodeID)
	newRequest.Header.Set("x-tyk-nodeid", NodeID)

	newRequest.Header.Set("x-tyk-nonce", ServiceNonce)

	c := &http.Client{
		Timeout: 120 * time.Second,
	}
	resp, err := c.Do(newRequest)
	if err != nil {
		log.Error("Request failed: ", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Error("Login failure, Response was: ", string(body))
		reLogin()
		return nil
	}

	// Extract tagged APIs#
	var list struct {
		Message []struct {
			ApiDefinition *apidef.APIDefinition `bson:"api_definition" json:"api_definition"`
		}
		Nonce string
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		log.Error("Failed to decode body: ", err)
		log.Info("--> Retrying in 5s")
		return nil
	}

	// Extract tagged entries only
	apiDefs := make([]*apidef.APIDefinition, 0)

	if config.Global.DBAppConfOptions.NodeIsSegmented {
		tagList := make(map[string]bool, len(config.Global.DBAppConfOptions.Tags))
		toLoad := make(map[string]*apidef.APIDefinition)

		for _, mt := range config.Global.DBAppConfOptions.Tags {
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
		spec := a.MakeSpec(def)
		specs = append(specs, spec)
	}

	// Set the nonce
	ServiceNonce = list.Nonce
	log.Debug("Loading APIS Finished: Nonce Set: ", ServiceNonce)

	return specs
}

// FromCloud will connect and download ApiDefintions from a Mongo DB instance.
func (a APIDefinitionLoader) FromRPC(orgId string) []*APISpec {
	if rpcEmergencyMode {
		return LoadDefinitionsFromRPCBackup()
	}

	store := RPCStorageHandler{UserKey: config.Global.SlaveOptions.APIKey, Address: config.Global.SlaveOptions.ConnectionString}
	if !store.Connect() {
		return nil
	}

	// enable segments
	var tags []string
	if config.Global.DBAppConfOptions.NodeIsSegmented {
		log.Info("Segmented node, loading: ", config.Global.DBAppConfOptions.Tags)
		tags = config.Global.DBAppConfOptions.Tags
	}

	apiCollection := store.GetApiDefinitions(orgId, tags)

	//store.Disconnect()

	if rpcLoadCount > 0 {
		saveRPCDefinitionsBackup(apiCollection)
	}

	return a.processRPCDefinitions(apiCollection)
}

func (a APIDefinitionLoader) processRPCDefinitions(apiCollection string) []*APISpec {

	var apiDefs []*apidef.APIDefinition
	if err := json.Unmarshal([]byte(apiCollection), &apiDefs); err != nil {
		log.Error("Failed decode: ", err)
		return nil
	}

	var specs []*APISpec
	for _, def := range apiDefs {
		def.DecodeFromDB()

		if config.Global.SlaveOptions.BindToSlugsInsteadOfListenPaths {
			newListenPath := "/" + def.Slug //+ "/"
			log.Warning("Binding to ",
				newListenPath,
				" instead of ",
				def.Proxy.ListenPath)

			def.Proxy.ListenPath = newListenPath
		}

		spec := a.MakeSpec(def)
		specs = append(specs, spec)
	}

	return specs
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
		spec := a.MakeSpec(def)
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
	apiLangIDsRegex := regexp.MustCompile(`{(.*?)}`)
	asRegexStr := apiLangIDsRegex.ReplaceAllString(stringSpec, `(.*?)`)
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

func (a APIDefinitionLoader) compileCachedPathSpec(paths []string) []URLSpec {
	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	urlSpec := []URLSpec{}

	for _, stringSpec := range paths {
		newSpec := URLSpec{}
		a.generateRegex(stringSpec, &newSpec, Cached)
		// Extend with method actions
		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

var apiTemplate = template.New("").Funcs(map[string]interface{}{
	"jsonMarshal": func(v interface{}) (string, error) {
		bs, err := json.Marshal(v)
		return string(bs), err
	},
})

func (a APIDefinitionLoader) loadFileTemplate(path string) (*template.Template, error) {
	log.Debug("-- Loading template: ", path)
	return apiTemplate.New("").ParseFiles(path)
}

func (a APIDefinitionLoader) loadBlobTemplate(blob string) (*template.Template, error) {
	log.Debug("-- Loading blob")
	uDec, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return nil, err
	}
	return apiTemplate.New("").Parse(string(uDec))
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
					log.Warning("[PROXY] [CIRCUIT BREKER] Breaker tripped for path: ", path)
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
							log.Warning("[PROXY] [CIRCUIT BREKER] Refreshing host list")
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
		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat)
		// Extend with method actions
		newSpec.URLRewrite = stringSpec

		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) compileVirtualPathspathSpec(paths []apidef.VirtualMeta, stat URLStatus, apiSpec *APISpec) []URLSpec {
	if !config.Global.EnableJSVM {
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

func (a APIDefinitionLoader) getExtendedPathSpecs(apiVersionDef apidef.VersionInfo, apiSpec *APISpec) ([]URLSpec, bool) {
	// TODO: New compiler here, needs to put data into a different structure

	ignoredPaths := a.compileExtendedPathSpec(apiVersionDef.ExtendedPaths.Ignored, Ignored)
	blackListPaths := a.compileExtendedPathSpec(apiVersionDef.ExtendedPaths.BlackList, BlackList)
	whiteListPaths := a.compileExtendedPathSpec(apiVersionDef.ExtendedPaths.WhiteList, WhiteList)
	cachedPaths := a.compileCachedPathSpec(apiVersionDef.ExtendedPaths.Cached)
	transformPaths := a.compileTransformPathSpec(apiVersionDef.ExtendedPaths.Transform, Transformed)
	transformResponsePaths := a.compileTransformPathSpec(apiVersionDef.ExtendedPaths.TransformResponse, TransformedResponse)
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

	combinedPath := []URLSpec{}
	combinedPath = append(combinedPath, ignoredPaths...)
	combinedPath = append(combinedPath, blackListPaths...)
	combinedPath = append(combinedPath, whiteListPaths...)
	combinedPath = append(combinedPath, cachedPaths...)
	combinedPath = append(combinedPath, transformPaths...)
	combinedPath = append(combinedPath, transformResponsePaths...)
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

	return combinedPath, len(whiteListPaths) > 0
}

func (a *APISpec) Init(authStore, sessionStore, healthStore, orgStore storage.Handler) {
	a.AuthManager.Init(authStore)
	a.SessionManager.Init(sessionStore)
	a.Health.Init(healthStore)
	a.OrgSessionManager.Init(orgStore)
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
	case HeaderInjected:
		return StatusHeaderInjected
	case HeaderInjectedResponse:
		return StatusHeaderInjectedResponse
	case TransformedResponse:
		return StatusTransformResponse
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
		return StatusRequesTracked
	case RequestNotTracked:
		return StatusRequestNotTracked
	case ValidateJSONRequest:
		return StatusValidateJSON

	default:
		log.Error("URL Status was not one of Ignored, Blacklist or WhiteList! Blocking.")
		return EndPointNotAllowed
	}
}

// URLAllowedAndIgnored checks if a url is allowed and ignored.
func (a *APISpec) URLAllowedAndIgnored(r *http.Request, rxPaths []URLSpec, whiteListStatus bool) (RequestStatus, interface{}) {
	// Check if ignored
	for _, v := range rxPaths {
		if !v.Spec.MatchString(strings.ToLower(r.URL.Path)) {
			continue
		}
		if v.MethodActions != nil {
			// We are using an extended path set, check for the method
			methodMeta, matchMethodOk := v.MethodActions[r.Method]

			if !matchMethodOk {
				continue
			}

			// Matched the method, check what status it is:
			if methodMeta.Action == apidef.NoAction {
				// NoAction status means we're not treating this request in any special or exceptional way
				return a.getURLStatus(v.Status), nil
			}
			// TODO: Extend here for additional reply options
			switch methodMeta.Action {
			case apidef.Reply:
				return StatusRedirectFlowByReply, &methodMeta
			default:
				log.Error("URL Method Action was not set to NoAction, blocking.")
				return EndPointNotAllowed, nil
			}
		}

		if v.TransformAction.Template != nil {
			return a.getURLStatus(v.Status), &v.TransformAction
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
	// Check if ignored
	for _, v := range rxPaths {
		if mode != v.Status {
			continue
		}
		match := v.Spec.MatchString(r.URL.Path)
		// only return it it's what we are looking for
		if !match {
			// check for special case when using url_rewrites with transform_response
			// and specifying the same "path" expression
			if mode != TransformedResponse {
				continue
			} else if v.TransformResponseAction.Path != ctxGetUrlRewritePath(r) {
				continue
			}
		}
		switch v.Status {
		case Ignored, BlackList, WhiteList, Cached:
			return true, nil
		case Transformed:
			if r.Method == v.TransformAction.Method {
				return true, &v.TransformAction
			}
		case HeaderInjected:
			if r.Method == v.InjectHeaders.Method {
				return true, &v.InjectHeaders
			}
		case HeaderInjectedResponse:
			if r.Method == v.InjectHeadersResponse.Method {
				return true, &v.InjectHeadersResponse
			}
		case TransformedResponse:
			if r.Method == v.TransformResponseAction.Method {
				return true, &v.TransformResponseAction
			}
		case HardTimeout:
			if r.Method == v.HardTimeout.Method {
				return true, &v.HardTimeout.TimeOut
			}
		case CircuitBreaker:
			if r.Method == v.CircuitBreaker.Method {
				return true, &v.CircuitBreaker
			}
		case URLRewrite:
			if r.Method == v.URLRewrite.Method {
				return true, &v.URLRewrite
			}
		case VirtualPath:
			if r.Method == v.VirtualPathSpec.Method {
				return true, &v.VirtualPathSpec
			}
		case RequestSizeLimit:
			if r.Method == v.RequestSize.Method {
				return true, &v.RequestSize
			}
		case MethodTransformed:
			if r.Method == v.MethodTransform.Method {
				return true, &v.MethodTransform
			}
		case RequestTracked:
			if r.Method == v.TrackEndpoint.Method {
				return true, &v.TrackEndpoint
			}
		case RequestNotTracked:
			if r.Method == v.DoNotTrackEndpoint.Method {
				return true, &v.DoNotTrackEndpoint
			}
		case ValidateJSONRequest:
			if r.Method == v.ValidatePathMeta.Method {
				return true, &v.ValidatePathMeta
			}
		}
	}
	return false, nil
}

func (a *APISpec) getVersionFromRequest(r *http.Request) string {
	switch a.VersionDefinition.Location {
	case "header":
		return r.Header.Get(a.VersionDefinition.Key)

	case "url-param":
		return r.URL.Query().Get(a.VersionDefinition.Key)

	case "url":
		url := strings.Replace(r.URL.Path, a.Proxy.ListenPath, "", 1)
		// First non-empty part of the path is the version ID
		for _, part := range strings.Split(url, "/") {
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

	// otherwise - calculate the time
	t, err := time.Parse("2006-01-02 15:04", versionDef.Expires)
	if err != nil {
		log.Error("Could not parse expiry date for API, dissallow: ", err)
		return true, nil
	}

	// It's in the past, expire
	// It's in the future, keep going
	return time.Since(t) >= 0, &t
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
			vname := a.getVersionFromRequest(r)
			if vname == "" && a.VersionData.DefaultVersion != "" {
				vname = a.VersionData.DefaultVersion
				ctxSetDefaultVersion(r)
			}
			if vname == "" && a.VersionData.DefaultVersion == "" {
				return &version, nil, false, VersionNotFound
			}
			// Load Version Data - General
			var ok bool
			if version, ok = a.VersionData.Versions[vname]; !ok {
				return &version, nil, false, VersionDoesNotExist
			}
		}

		// cache for the future
		ctxSetVersionInfo(r, &version)
	}

	// Load path data and whitelist data for version
	rxPaths, rxOk := a.RxPaths[version.Name]
	whiteListStatus, wlOk := a.WhiteListEnabled[version.Name]

	if !rxOk {
		log.Error("no RX Paths found for version ", version.Name)
		return &version, nil, false, VersionDoesNotExist
	}

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

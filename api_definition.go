package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	textTemplate "text/template"
	"time"

	"github.com/gorilla/context"
	"github.com/rubyist/circuitbreaker"

	"github.com/TykTechnologies/tyk/apidef"
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
}

type TransformSpec struct {
	apidef.TemplateMeta
	Template *textTemplate.Template
}

type ExtendedCircuitBreakerMeta struct {
	apidef.CircuitBreakerMeta
	CB *circuit.Breaker
}

// APISpec represents a path specification for an API, to avoid enumerating multiple nested lists, a single
// flattened URL list is checked for matching paths and then it's status evaluated if found.
type APISpec struct {
	*apidef.APIDefinition

	RxPaths                  map[string][]URLSpec
	WhiteListEnabled         map[string]bool
	target                   *url.URL
	AuthManager              AuthorisationHandler
	SessionManager           SessionHandler
	OAuthManager             *OAuthManager
	OrgSessionManager        SessionHandler
	EventPaths               map[apidef.TykEvent][]TykEventHandler
	Health                   HealthChecker
	JSVM                     *JSVM
	ResponseChain            []TykResponseHandler
	RoundRobin               RoundRobin
	URLRewriteEnabled        bool
	CircuitBreakerEnabled    bool
	EnforcedTimeoutEnabled   bool
	ResponseHandlersActive   bool
	LastGoodHostList         *apidef.HostList
	HasRun                   bool
	ServiceRefreshInProgress bool
}

// APIDefinitionLoader will load an Api definition from a storage system. It has two methods LoadDefinitionsFromMongo()
// and LoadDefinitions(), each will pull api specifications from different locations.
type APIDefinitionLoader struct{}

// Nonce to use when interacting with the dashboard service
var ServiceNonce string

// MakeSpec will generate a flattened URLSpec from and APIDefinitions' VersionInfo data. paths are
// keyed to the Api version name, which is determined during routing to speed up lookups
func (a *APIDefinitionLoader) MakeSpec(appConfig *apidef.APIDefinition) *APISpec {
	newAppSpec := &APISpec{}
	newAppSpec.APIDefinition = appConfig

	// We'll push the default HealthChecker:
	newAppSpec.Health = &DefaultHealthChecker{
		APIID: newAppSpec.APIID,
	}

	// Add any new session managers or auth handlers here
	newAppSpec.AuthManager = &DefaultAuthorisationManager{}

	newAppSpec.SessionManager = &DefaultSessionManager{}
	newAppSpec.OrgSessionManager = &DefaultSessionManager{}

	// Create and init the virtual Machine
	if config.EnableJSVM {
		newAppSpec.JSVM = &JSVM{}
		newAppSpec.JSVM.Init(config.TykJSPath)
	}

	// Set up Event Handlers
	log.Debug("INITIALISING EVENT HANDLERS")
	newAppSpec.EventPaths = make(map[apidef.TykEvent][]TykEventHandler)
	for eventName, eventHandlerConfs := range appConfig.EventHandlers.Events {
		log.Debug("FOUND EVENTS TO INIT")
		for _, handlerConf := range eventHandlerConfs {
			log.Debug("CREATING EVENT HANDLERS")
			eventHandlerInstance, err := GetEventHandlerByName(handlerConf, newAppSpec)

			if err != nil {
				log.Error("Failed to init event handler: ", err)
			} else {
				log.Debug("Init Event Handler: ", eventName)
				newAppSpec.EventPaths[eventName] = append(newAppSpec.EventPaths[eventName], eventHandlerInstance)
			}

		}
	}

	newAppSpec.RxPaths = make(map[string][]URLSpec, len(appConfig.VersionData.Versions))
	newAppSpec.WhiteListEnabled = make(map[string]bool, len(appConfig.VersionData.Versions))
	for _, v := range appConfig.VersionData.Versions {
		var pathSpecs []URLSpec
		var whiteListSpecs bool

		// If we have transitioned to extended path specifications, we should use these now
		if v.UseExtendedPaths {
			pathSpecs, whiteListSpecs = a.getExtendedPathSpecs(v, newAppSpec)

		} else {
			log.Warning("Legacy path detected! Upgrade to extended.")
			pathSpecs, whiteListSpecs = a.getPathSpecs(v)
		}
		newAppSpec.RxPaths[v.Name] = pathSpecs
		newAppSpec.WhiteListEnabled[v.Name] = whiteListSpecs
	}

	return newAppSpec
}

func (a *APIDefinitionLoader) readBody(response *http.Response) ([]byte, error) {
	defer response.Body.Close()
	return ioutil.ReadAll(response.Body)
}

// LoadDefinitionsFromDashboardService will connect and download ApiDefintions from a Tyk Dashboard instance.
func (a *APIDefinitionLoader) LoadDefinitionsFromDashboardService(endpoint, secret string) []*APISpec {
	// Get the definitions
	log.Debug("Calling: ", endpoint)
	newRequest, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		log.Error("Failed to create request: ", err)
	}

	newRequest.Header.Add("authorization", secret)
	log.Debug("Using: NodeID: ", NodeID)
	newRequest.Header.Add("x-tyk-nodeid", NodeID)

	newRequest.Header.Add("x-tyk-nonce", ServiceNonce)

	c := &http.Client{
		Timeout: 120 * time.Second,
	}
	response, err := c.Do(newRequest)
	if err != nil {
		log.Error("Request failed: ", err)
		return nil
	}

	retBody, err := a.readBody(response)
	if err != nil {
		log.Error("Failed to read body: ", err)
		return nil
	}

	if response.StatusCode == 403 {
		log.Error("Login failure, Response was: ", string(retBody))
		reLogin()
		return nil
	}

	// Extract tagged APIs#

	type ResponseStruct struct {
		ApiDefinition *apidef.APIDefinition `bson:"api_definition" json:"api_definition"`
	}
	type NodeResponseOK struct {
		Status  string
		Message []ResponseStruct
		Nonce   string
	}

	list := NodeResponseOK{}
	if err := json.Unmarshal(retBody, &list); err != nil {
		log.Error("Failed to decode body: ", err, "Response was: ", string(retBody))
		log.Info("--> Retrying in 5s")
		return nil
	}

	rawList := make(map[string]interface{})
	if err := json.Unmarshal(retBody, &rawList); err != nil {
		log.Error("Failed to decode body (raw): ", err)
		return nil
	}

	// Extract tagged entries only
	apiDefs := make([]*apidef.APIDefinition, 0)

	if config.DBAppConfOptions.NodeIsSegmented {
		tagList := make(map[string]bool, len(config.DBAppConfOptions.Tags))
		toLoad := make(map[string]*apidef.APIDefinition)

		for _, mt := range config.DBAppConfOptions.Tags {
			tagList[mt] = true
		}

		for index, apiEntry := range list.Message {
			for _, t := range apiEntry.ApiDefinition.Tags {
				if tagList[t] {
					apiEntry.ApiDefinition.RawData = rawList["Message"].([]interface{})[index].(map[string]interface{})["api_definition"].(map[string]interface{})
					toLoad[apiEntry.ApiDefinition.APIID] = apiEntry.ApiDefinition
				}

			}
		}

		for _, apiDef := range toLoad {
			apiDefs = append(apiDefs, apiDef)
		}
	} else {
		for index, apiEntry := range list.Message {
			apiEntry.ApiDefinition.RawData = rawList["Message"].([]interface{})[index].(map[string]interface{})["api_definition"].(map[string]interface{})
			apiDefs = append(apiDefs, apiEntry.ApiDefinition)
		}
	}

	// Process
	var apiSpecs []*APISpec
	for _, appConfig := range apiDefs {
		newAppSpec := a.MakeSpec(appConfig)
		apiSpecs = append(apiSpecs, newAppSpec)
	}

	// Set the nonce
	ServiceNonce = list.Nonce
	log.Debug("Loading APIS Finished: Nonce Set: ", ServiceNonce)

	return apiSpecs
}

// LoadDefinitionsFromCloud will connect and download ApiDefintions from a Mongo DB instance.
func (a *APIDefinitionLoader) LoadDefinitionsFromRPC(orgId string) []*APISpec {
	store := RPCStorageHandler{UserKey: config.SlaveOptions.APIKey, Address: config.SlaveOptions.ConnectionString}
	store.Connect()

	// enable segments
	var tags []string
	if config.DBAppConfOptions.NodeIsSegmented {
		log.Info("Segmented node, loading: ", config.DBAppConfOptions.Tags)
		tags = config.DBAppConfOptions.Tags
	}

	apiCollection := store.GetApiDefinitions(orgId, tags)

	//store.Disconnect()

	if RPC_LoadCount > 0 {
		SaveRPCDefinitionsBackup(apiCollection)
	}

	return a.processRPCDefinitions(apiCollection)
}

func (a *APIDefinitionLoader) processRPCDefinitions(apiCollection string) []*APISpec {

	var apiDefs []*apidef.APIDefinition
	if err := json.Unmarshal([]byte(apiCollection), &apiDefs); err != nil {
		log.Error("Failed decode: ", err)
		return nil
	}
	var strDefs []map[string]interface{}
	if err := json.Unmarshal([]byte(apiCollection), &strDefs); err != nil {
		log.Error("Failed decode: ", err)
		return nil
	}

	var apiSpecs []*APISpec
	for i, appConfig := range apiDefs {
		appConfig.DecodeFromDB()
		appConfig.RawData = strDefs[i] // Lets keep a copy for plugable modules

		if config.SlaveOptions.BindToSlugsInsteadOfListenPaths {
			newListenPath := "/" + appConfig.Slug //+ "/"
			log.Warning("Binding to ",
				newListenPath,
				" instead of ",
				appConfig.Proxy.ListenPath)

			appConfig.Proxy.ListenPath = newListenPath
		}

		newAppSpec := a.MakeSpec(appConfig)
		apiSpecs = append(apiSpecs, newAppSpec)
	}

	return apiSpecs
}

func (a *APIDefinitionLoader) ParseDefinition(apiDef []byte) (*apidef.APIDefinition, map[string]interface{}) {
	appConfig := &apidef.APIDefinition{}
	if err := json.Unmarshal(apiDef, appConfig); err != nil {
		log.Error("[RPC] --> Couldn't unmarshal api configuration: ", err)
	}

	// Got the structured version - now lets get a raw copy for modules
	rawConfig := make(map[string]interface{})
	json.Unmarshal(apiDef, &rawConfig)

	return appConfig, rawConfig
}

// LoadDefinitions will load APIDefinitions from a directory on the filesystem. Definitions need
// to be the JSON representation of APIDefinition object
func (a *APIDefinitionLoader) LoadDefinitions(dir string) []*APISpec {
	var apiSpecs []*APISpec
	// Grab json files from directory
	files, _ := ioutil.ReadDir(dir)
	for _, f := range files {
		if strings.Contains(f.Name(), ".json") {
			filePath := filepath.Join(dir, f.Name())
			log.Info("Loading API Specification from ", filePath)
			appConfigBody, err := ioutil.ReadFile(filePath)
			appConfig, rawConfig := a.ParseDefinition(appConfigBody)
			if err != nil {
				log.Error("Couldn't load app configuration file: ", err)
			}

			appConfig.RawData = rawConfig // Lets keep a copy for plugable modules
			newAppSpec := a.MakeSpec(appConfig)
			apiSpecs = append(apiSpecs, newAppSpec)

		}
	}

	return apiSpecs
}

func (a *APIDefinitionLoader) getPathSpecs(apiVersionDef apidef.VersionInfo) ([]URLSpec, bool) {
	ignoredPaths := a.compilePathSpec(apiVersionDef.Paths.Ignored, Ignored)
	blackListPaths := a.compilePathSpec(apiVersionDef.Paths.BlackList, BlackList)
	whiteListPaths := a.compilePathSpec(apiVersionDef.Paths.WhiteList, WhiteList)

	combinedPath := []URLSpec{}
	combinedPath = append(combinedPath, ignoredPaths...)
	combinedPath = append(combinedPath, blackListPaths...)
	combinedPath = append(combinedPath, whiteListPaths...)

	return combinedPath, len(whiteListPaths) > 0
}

func (a *APIDefinitionLoader) generateRegex(stringSpec string, newSpec *URLSpec, specType URLStatus) {
	apiLangIDsRegex := regexp.MustCompile(`{(.*?)}`)
	asRegexStr := apiLangIDsRegex.ReplaceAllString(stringSpec, `(.*?)`)
	asRegex := regexp.MustCompile(asRegexStr)
	newSpec.Status = specType
	newSpec.Spec = asRegex
}

func (a *APIDefinitionLoader) compilePathSpec(paths []string, specType URLStatus) []URLSpec {
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

func (a *APIDefinitionLoader) compileExtendedPathSpec(paths []apidef.EndPointMeta, specType URLStatus) []URLSpec {
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

func (a *APIDefinitionLoader) compileCachedPathSpec(paths []string) []URLSpec {
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

func (a *APIDefinitionLoader) loadFileTemplate(path string) (*textTemplate.Template, error) {
	log.Debug("-- Loading template: ", path)
	return textTemplate.ParseFiles(path)
}

func (a *APIDefinitionLoader) loadBlobTemplate(blob string) (*textTemplate.Template, error) {
	log.Debug("-- Loading blob")
	uDec, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return nil, err
	}
	return textTemplate.New("blob").Parse(string(uDec))
}

func (a *APIDefinitionLoader) compileTransformPathSpec(paths []apidef.TemplateMeta, stat URLStatus) []URLSpec {
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

func (a *APIDefinitionLoader) compileInjectedHeaderSpec(paths []apidef.HeaderInjectionMeta, stat URLStatus) []URLSpec {
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

func (a *APIDefinitionLoader) compileMethodTransformSpec(paths []apidef.MethodTransformMeta, stat URLStatus) []URLSpec {
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

func (a *APIDefinitionLoader) compileTimeoutPathSpec(paths []apidef.HardTimeoutMeta, stat URLStatus) []URLSpec {
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

func (a *APIDefinitionLoader) compileRequestSizePathSpec(paths []apidef.RequestSizeMeta, stat URLStatus) []URLSpec {
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

func (a *APIDefinitionLoader) compileCircuitBreakerPathSpec(paths []apidef.CircuitBreakerMeta, stat URLStatus, apiSpec *APISpec) []URLSpec {
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
			for {
				e := <-events
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

func (a *APIDefinitionLoader) compileURLRewritesPathSpec(paths []apidef.URLRewriteMeta, stat URLStatus) []URLSpec {
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

func (a *APIDefinitionLoader) compileVirtualPathspathSpec(paths []apidef.VirtualMeta, stat URLStatus, apiSpec *APISpec) []URLSpec {
	if !config.EnableJSVM {
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

		PreLoadVirtualMetaCode(&newSpec.VirtualPathSpec, apiSpec.JSVM)

		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a *APIDefinitionLoader) compileTrackedEndpointPathspathSpec(paths []apidef.TrackEndpointMeta, stat URLStatus) []URLSpec {
	urlSpec := []URLSpec{}

	for _, stringSpec := range paths {
		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat)
		// Extend with method actions
		newSpec.TrackEndpoint = stringSpec
		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a *APIDefinitionLoader) compileUnTrackedEndpointPathspathSpec(paths []apidef.TrackEndpointMeta, stat URLStatus) []URLSpec {
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

func (a *APIDefinitionLoader) getExtendedPathSpecs(apiVersionDef apidef.VersionInfo, apiSpec *APISpec) ([]URLSpec, bool) {
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

	return combinedPath, len(whiteListPaths) > 0
}

func (a *APISpec) Init(authStore, sessionStore, healthStore, orgStore StorageHandler) {
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
	default:
		log.Error("URL Status was not one of Ignored, Blacklist or WhiteList! Blocking.")
		return EndPointNotAllowed
	}
}

// IsURLAllowedAndIgnored checks if a url is allowed and ignored.
func (a *APISpec) IsURLAllowedAndIgnored(method, url string, rxPaths []URLSpec, whiteListStatus bool) (RequestStatus, interface{}) {
	// Check if ignored
	for _, v := range rxPaths {
		if !v.Spec.MatchString(strings.ToLower(url)) {
			continue
		}
		if v.MethodActions != nil {
			// We are using an extended path set, check for the method
			methodMeta, matchMethodOk := v.MethodActions[method]
			if matchMethodOk {
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

			if whiteListStatus {
				// We have a whitelist, nothing gets through unless specifically defined
				return EndPointNotAllowed, nil
			}

			// Method not matched in an extended set, means it can be passed through
			return StatusOk, nil
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
func (a *APISpec) CheckSpecMatchesStatus(url string, method string, rxPaths []URLSpec, mode URLStatus) (bool, interface{}) {
	// Check if ignored
	for _, v := range rxPaths {
		match := v.Spec.MatchString(url)
		// only return it it's what we are looking for
		if !match || mode != v.Status {
			continue
		}
		switch v.Status {
		case Ignored, BlackList, WhiteList, Cached:
			return true, nil
		case Transformed:
			if method == v.TransformAction.TemplateMeta.Method {
				return true, &v.TransformAction
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
			if method == v.TransformResponseAction.TemplateMeta.Method {
				return true, &v.TransformResponseAction
			}
		case HardTimeout:
			if method == v.HardTimeout.Method {
				return true, &v.HardTimeout.TimeOut
			}
		case CircuitBreaker:
			if method == v.CircuitBreaker.Method {
				return true, &v.CircuitBreaker
			}
		case URLRewrite:
			if method == v.URLRewrite.Method {
				return true, &v.URLRewrite
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
		}
	}
	return false, nil
}

func (a *APISpec) getVersionFromRequest(r *http.Request) string {
	switch a.APIDefinition.VersionDefinition.Location {
	case "header":
		return r.Header.Get(a.APIDefinition.VersionDefinition.Key)

	case "url-param":
		tempRes := CopyRequest(r)
		return tempRes.FormValue(a.APIDefinition.VersionDefinition.Key)

	case "url":
		url := strings.Replace(r.URL.Path, a.Proxy.ListenPath, "", 1)
		if len(url) == 0 {
			return ""
		}
		if url[:1] == "/" {
			url = url[1:]
		}

		// Assume first param is the version ID
		firstParamEndsAt := strings.Index(url, "/")
		if firstParamEndsAt == -1 {
			return ""
		}

		return url[:firstParamEndsAt]
	}
	return ""
}

// IsThisAPIVersionExpired checks if an API version (during a proxied request) is expired
func (a *APISpec) IsThisAPIVersionExpired(versionDef *apidef.VersionInfo) bool {
	// Never expires
	if versionDef.Expires == "" || versionDef.Expires == "-1" {
		return false
	}

	// otherwise - calculate the time
	t, err := time.Parse("2006-01-02 15:04", versionDef.Expires)
	if err != nil {
		log.Error("Could not parse expiry date for API, dissallow: ", err)
		return true
	}

	// It's in the past, expire
	// It's in the future, keep going
	return time.Since(t) >= 0
}

// IsRequestValid will check if an incoming request has valid version data and return a RequestStatus that
// describes the status of the request
func (a *APISpec) IsRequestValid(r *http.Request) (bool, RequestStatus, interface{}) {
	versionMetaData, versionPaths, whiteListStatus, stat := a.GetVersionData(r)

	// Screwed up version info - fail and pass through
	if stat != StatusOk {
		return false, stat, nil
	}

	// Is the API version expired?
	if a.IsThisAPIVersionExpired(versionMetaData) {
		// Expired - fail
		return false, VersionExpired, nil
	}

	// not expired, let's check path info
	requestStatus, meta := a.IsURLAllowedAndIgnored(r.Method, r.URL.Path, versionPaths, whiteListStatus)

	switch requestStatus {
	case EndPointNotAllowed:
		return false, EndPointNotAllowed, meta
	case StatusOkAndIgnore:
		return true, StatusOkAndIgnore, meta
	case StatusRedirectFlowByReply:
		return true, StatusRedirectFlowByReply, meta
	case StatusCached:
		return true, StatusCached, meta
	case StatusTransform:
		return true, StatusTransform, meta
	case StatusHeaderInjected:
		return true, StatusHeaderInjected, meta
	case StatusMethodTransformed:
		return true, StatusMethodTransformed, meta
	default:
		return true, StatusOk, meta
	}

}

// GetVersionData attempts to extract the version data from a request, depending on where it is stored in the
// request (currently only "header" is supported)
func (a *APISpec) GetVersionData(r *http.Request) (*apidef.VersionInfo, []URLSpec, bool, RequestStatus) {
	var version apidef.VersionInfo
	var versionKey string
	var versionRxPaths []URLSpec
	var versionWLStatus bool

	// try the context first
	aVersion, foundInContext := context.GetOk(r, VersionData)

	if foundInContext {
		version = aVersion.(apidef.VersionInfo)
		versionKey = context.Get(r, VersionKeyContext).(string)
	} else {
		// Are we versioned?
		if a.APIDefinition.VersionData.NotVersioned {
			// Get the first one in the list
			for k, v := range a.APIDefinition.VersionData.Versions {
				versionKey = k
				version = v
				break
			}
		} else {
			// Extract Version Info
			versionKey = a.getVersionFromRequest(r)
			if versionKey == "" {
				return &version, versionRxPaths, versionWLStatus, VersionNotFound
			}
		}

		// Load Version Data - General
		var ok bool
		version, ok = a.APIDefinition.VersionData.Versions[versionKey]
		if !ok {
			return &version, versionRxPaths, versionWLStatus, VersionDoesNotExist
		}

		// Lets save this for the future
		context.Set(r, VersionData, version)
		context.Set(r, VersionKeyContext, versionKey)
	}

	// Load path data and whitelist data for version
	rxPaths, rxOk := a.RxPaths[versionKey]
	whiteListStatus, wlOk := a.WhiteListEnabled[versionKey]

	if !rxOk {
		log.Error("no RX Paths found for version ", versionKey)
		return &version, versionRxPaths, versionWLStatus, VersionDoesNotExist
	}

	if !wlOk {
		log.Error("No whitelist data found")
		return &version, versionRxPaths, versionWLStatus, VersionWhiteListStatusNotFound
	}

	versionRxPaths = rxPaths
	versionWLStatus = whiteListStatus

	return &version, versionRxPaths, versionWLStatus, StatusOk

}

type RoundRobin struct {
	pos, max, cur int
}

func (r *RoundRobin) SetMax(max int) {
	if r.max = max; r.max < 0 {
		r.max = 0
	}

	// Can't have a new list substituted that's shorter
	if r.cur > r.max {
		r.cur = 0
	}
	if r.pos > r.max {
		r.pos = 0
	}
}

func (r *RoundRobin) SetLen(len int) { r.SetMax(len - 1) }

func (r *RoundRobin) GetPos() int {
	r.cur = r.pos
	if r.pos++; r.pos > r.max {
		r.pos = 0
	}
	return r.cur
}

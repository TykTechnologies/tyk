package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"regexp"
	textTemplate "text/template"
	"time"

	"github.com/rubyist/circuitbreaker"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/load_balancer"
)

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
	if globalConf.EnableJSVM {
		spec.JSVM.Init(&globalConf, &APIHandle)
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
	type ResponseStruct struct {
		ApiDefinition *apidef.APIDefinition `bson:"api_definition" json:"api_definition"`
	}
	type NodeResponseOK struct {
		Status  string
		Message []ResponseStruct
		Nonce   string
	}

	list := NodeResponseOK{}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		log.Error("Failed to decode body: ", err)
		log.Info("--> Retrying in 5s")
		return nil
	}

	// Extract tagged entries only
	apiDefs := make([]*apidef.APIDefinition, 0)

	if globalConf.DBAppConfOptions.NodeIsSegmented {
		tagList := make(map[string]bool, len(globalConf.DBAppConfOptions.Tags))
		toLoad := make(map[string]*apidef.APIDefinition)

		for _, mt := range globalConf.DBAppConfOptions.Tags {
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
	var apiSpecs []*APISpec
	for _, def := range apiDefs {
		spec := a.MakeSpec(def)
		apiSpecs = append(apiSpecs, spec)
	}

	// Set the nonce
	ServiceNonce = list.Nonce
	log.Debug("Loading APIS Finished: Nonce Set: ", ServiceNonce)

	return apiSpecs
}

// FromCloud will connect and download ApiDefintions from a Mongo DB instance.
func (a APIDefinitionLoader) FromRPC(orgId string) []*APISpec {
	store := RPCStorageHandler{UserKey: globalConf.SlaveOptions.APIKey, Address: globalConf.SlaveOptions.ConnectionString}
	store.Connect()

	// enable segments
	var tags []string
	if globalConf.DBAppConfOptions.NodeIsSegmented {
		log.Info("Segmented node, loading: ", globalConf.DBAppConfOptions.Tags)
		tags = globalConf.DBAppConfOptions.Tags
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

	var apiSpecs []*APISpec
	for _, def := range apiDefs {
		def.DecodeFromDB()

		if globalConf.SlaveOptions.BindToSlugsInsteadOfListenPaths {
			newListenPath := "/" + def.Slug //+ "/"
			log.Warning("Binding to ",
				newListenPath,
				" instead of ",
				def.Proxy.ListenPath)

			def.Proxy.ListenPath = newListenPath
		}

		spec := a.MakeSpec(def)
		apiSpecs = append(apiSpecs, spec)
	}

	return apiSpecs
}

func (a APIDefinitionLoader) ParseDefinition(apiDef []byte) *apidef.APIDefinition {
	def := &apidef.APIDefinition{}
	if err := json.Unmarshal(apiDef, def); err != nil {
		log.Error("[RPC] --> Couldn't unmarshal api configuration: ", err)
	}
	return def
}

// FromDir will load APIDefinitions from a directory on the filesystem. Definitions need
// to be the JSON representation of APIDefinition object
func (a APIDefinitionLoader) FromDir(dir string) []*APISpec {
	var apiSpecs []*APISpec
	// Grab json files from directory
	paths, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	for _, path := range paths {
		log.Info("Loading API Specification from ", path)
		defBody, err := ioutil.ReadFile(path)
		if err != nil {
			log.Error("Couldn't load app configuration file: ", err)
			continue
		}
		def := a.ParseDefinition(defBody)
		spec := a.MakeSpec(def)
		apiSpecs = append(apiSpecs, spec)
	}
	return apiSpecs
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
	asRegex := regexp.MustCompile(asRegexStr)
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

func (a APIDefinitionLoader) loadFileTemplate(path string) (*textTemplate.Template, error) {
	log.Debug("-- Loading template: ", path)
	return textTemplate.ParseFiles(path)
}

func (a APIDefinitionLoader) loadBlobTemplate(blob string) (*textTemplate.Template, error) {
	log.Debug("-- Loading blob")
	uDec, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return nil, err
	}
	return textTemplate.New("blob").Parse(string(uDec))
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
	if !globalConf.EnableJSVM {
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
		// Extend with method actions
		newSpec.TrackEndpoint = stringSpec
		urlSpec = append(urlSpec, newSpec)
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


type RoundRobin = load_balancer.RoundRobin

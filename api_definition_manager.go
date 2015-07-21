package main

import (
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"github.com/gorilla/context"
	"github.com/lonelycode/tykcommon"
	"github.com/rubyist/circuitbreaker"
	"io/ioutil"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	textTemplate "text/template"
	"time"
)

const (
	DefaultAuthProvider    tykcommon.AuthProviderCode    = "default"
	DefaultSessionProvider tykcommon.SessionProviderCode = "default"
	DefaultStorageEngine   tykcommon.StorageEngineCode   = "redis"
	LDAPStorageEngine      tykcommon.StorageEngineCode   = "ldap"
	RPCStorageEngine       tykcommon.StorageEngineCode   = "rpc"
)

// URLStatus is a custom enum type to avoid collisions
type URLStatus int

// Enums representing the various statuses for a VersionInfo Path match during a
// proxy request
const (
	Ignored                URLStatus = 1
	WhiteList              URLStatus = 2
	BlackList              URLStatus = 3
	Cached                 URLStatus = 4
	Transformed            URLStatus = 5
	HeaderInjected         URLStatus = 6
	HeaderInjectedResponse URLStatus = 7
	TransformedResponse    URLStatus = 8
	HardTimeout            URLStatus = 9
	CircuitBreaker         URLStatus = 10
	URLRewrite             URLStatus = 11
)

// RequestStatus is a custom type to avoid collisions
type RequestStatus string

// Statuses of the request, all are false-y except StatusOk and StatusOkAndIgnore
const (
	VersionNotFound                RequestStatus = "Version information not found"
	VersionDoesNotExist            RequestStatus = "This API version does not seem to exist"
	VersionPathsNotFound           RequestStatus = "Path information could not be found for version"
	VersionWhiteListStatusNotFound               = "WhiteListStatus for path not found"
	VersionExpired                 RequestStatus = "Api Version has expired, please check documentation or contact administrator"
	EndPointNotAllowed             RequestStatus = "Requested endpoint is forbidden"
	GeneralFailure                 RequestStatus = "An error occured that should have not been possible"
	StatusOkAndIgnore              RequestStatus = "Everything OK, passing and not filtering"
	StatusOk                       RequestStatus = "Everything OK, passing"
	StatusCached                   RequestStatus = "Cached path"
	StatusTransform                RequestStatus = "Transformed path"
	StatusTransformResponse        RequestStatus = "Transformed response"
	StatusHeaderInjected           RequestStatus = "Header injected"
	StatusHeaderInjectedResponse   RequestStatus = "Header injected on response"
	StatusActionRedirect           RequestStatus = "Found an Action, changing route"
	StatusRedirectFlowByReply      RequestStatus = "Exceptional action requested, redirecting flow!"
	StatusHardTimeout              RequestStatus = "Hard Timeout enforced on path"
	StatusCircuitBreaker           RequestStatus = "Circuit breaker enforced"
	StatusURLRewrite               RequestStatus = "URL Rewritten"
)

// URLSpec represents a flattened specification for URLs, used to check if a proxy URL
// path is on any of the white, plack or ignored lists. This is generated as part of the
// configuration init
type URLSpec struct {
	Spec                    *regexp.Regexp
	Status                  URLStatus
	MethodActions           map[string]tykcommon.EndpointMethodMeta
	TransformAction         TransformSpec
	TransformResponseAction TransformSpec
	InjectHeaders           tykcommon.HeaderInjectionMeta
	InjectHeadersResponse   tykcommon.HeaderInjectionMeta
	HardTimeout             tykcommon.HardTimeoutMeta
	CircuitBreaker          ExtendedCircuitBreakerMeta
	URLRewrite              tykcommon.URLRewriteMeta
}

type TransformSpec struct {
	tykcommon.TemplateMeta
	Template *textTemplate.Template
}

type ExtendedCircuitBreakerMeta struct {
	tykcommon.CircuitBreakerMeta
	CB *circuit.Breaker
}

// APISpec represents a path specification for an API, to avoid enumerating multiple nested lists, a single
// flattened URL list is checked for matching paths and then it's status evaluated if found.
type APISpec struct {
	tykcommon.APIDefinition
	RxPaths           map[string][]URLSpec
	WhiteListEnabled  map[string]bool
	target            *url.URL
	AuthManager       AuthorisationHandler
	SessionManager    SessionHandler
	OAuthManager      *OAuthManager
	OrgSessionManager SessionHandler
	EventPaths        map[tykcommon.TykEvent][]TykEventHandler
	Health            HealthChecker
	JSVM              *JSVM
	ResponseChain     *[]TykResponseHandler
	RoundRobin        *RoundRobin
}

// APIDefinitionLoader will load an Api definition from a storage system. It has two methods LoadDefinitionsFromMongo()
// and LoadDefinitions(), each will pull api specifications from different locations.
type APIDefinitionLoader struct {
	dbSession *mgo.Session
}

// Connect connects to the storage engine - can be null
func (a *APIDefinitionLoader) Connect() {
	var err error
	a.dbSession, err = mgo.Dial(config.AnalyticsConfig.MongoURL)
	if err != nil {
		log.Error("Mongo connection failed:")
		log.Panic(err)
	}
}

// MakeSpec will generate a flattened URLSpec from and APIDefinitions' VersionInfo data. paths are
// keyed to the Api version name, which is determined during routing to speed up lookups
func (a *APIDefinitionLoader) MakeSpec(thisAppConfig tykcommon.APIDefinition) APISpec {
	newAppSpec := APISpec{}
	newAppSpec.APIDefinition = thisAppConfig

	// We'll push the default HealthChecker:
	newAppSpec.Health = &DefaultHealthChecker{
		APIID: newAppSpec.APIID,
	}

	// Add any new session managers or auth handlers here
	if newAppSpec.APIDefinition.AuthProvider.Name != "" {
		switch newAppSpec.APIDefinition.AuthProvider.Name {
		case DefaultAuthProvider:
			newAppSpec.AuthManager = &DefaultAuthorisationManager{}
		default:
			newAppSpec.AuthManager = &DefaultAuthorisationManager{}
		}
	} else {
		newAppSpec.AuthManager = &DefaultAuthorisationManager{}
	}

	if newAppSpec.APIDefinition.SessionProvider.Name != "" {
		switch newAppSpec.APIDefinition.SessionProvider.Name {
		case DefaultSessionProvider:
			newAppSpec.SessionManager = &DefaultSessionManager{}
			newAppSpec.OrgSessionManager = &DefaultSessionManager{}
		default:
			newAppSpec.SessionManager = &DefaultSessionManager{}
			newAppSpec.OrgSessionManager = &DefaultSessionManager{}
		}
	} else {
		newAppSpec.SessionManager = &DefaultSessionManager{}
		newAppSpec.OrgSessionManager = &DefaultSessionManager{}
	}

	// Create and init the virtual Machine
	newAppSpec.JSVM = &JSVM{}
	newAppSpec.JSVM.Init(config.TykJSPath)

	// Set up Event Handlers
	log.Debug("INITIALISING EVENT HANDLERS")
	newAppSpec.EventPaths = make(map[tykcommon.TykEvent][]TykEventHandler)
	for eventName, eventHandlerConfs := range thisAppConfig.EventHandlers.Events {
		log.Debug("FOUND EVENTS TO INIT")
		for _, handlerConf := range eventHandlerConfs {
			log.Debug("CREATING EVENT HANDLERS")
			thisEventHandlerInstance, getHandlerErr := GetEventHandlerByName(handlerConf, &newAppSpec)

			if getHandlerErr != nil {
				log.Error("Failed to init event handler: ", getHandlerErr)
			} else {
				log.Debug("Init Event Handler: ", eventName)
				newAppSpec.EventPaths[eventName] = append(newAppSpec.EventPaths[eventName], thisEventHandlerInstance)
			}

		}
	}

	newAppSpec.RxPaths = make(map[string][]URLSpec)
	newAppSpec.WhiteListEnabled = make(map[string]bool)
	for _, v := range thisAppConfig.VersionData.Versions {
		var pathSpecs []URLSpec
		var whiteListSpecs bool

		// If we have transitioned to extended path specifications, we should use these now
		if v.UseExtendedPaths {
			pathSpecs, whiteListSpecs = a.getExtendedPathSpecs(v, &newAppSpec)

		} else {
			log.Warning("Path-based version path list settings are being deprecated, please upgrade your defintitions to the new standard as soon as spossible")
			pathSpecs, whiteListSpecs = a.getPathSpecs(v)
		}
		newAppSpec.RxPaths[v.Name] = pathSpecs
		newAppSpec.WhiteListEnabled[v.Name] = whiteListSpecs
	}

	return newAppSpec
}

// LoadDefinitionsFromMongo will connect and download ApiDefintions from a Mongo DB instance.
func (a *APIDefinitionLoader) LoadDefinitionsFromMongo() []APISpec {
	var APISpecs = []APISpec{}

	a.Connect()
	apiCollection := a.dbSession.DB("").C("tyk_apis")

	search := bson.M{
		"active": true,
	}

	var APIDefinitions = []tykcommon.APIDefinition{}
	var StringDefs = make([]bson.M, 0)
	mongoErr := apiCollection.Find(search).All(&APIDefinitions)

	if mongoErr != nil {
		log.Error("Could not find any application configs!: ", mongoErr)
		return APISpecs
	}

	apiCollection.Find(search).All(&StringDefs)

	for i, thisAppConfig := range APIDefinitions {
		thisAppConfig.DecodeFromDB()
		thisAppConfig.RawData = StringDefs[i] // Lets keep a copy for plugable modules

		newAppSpec := a.MakeSpec(thisAppConfig)
		APISpecs = append(APISpecs, newAppSpec)
	}
	return APISpecs
}

// LoadDefinitionsFromCloud will connect and download ApiDefintions from a Mongo DB instance.
func (a *APIDefinitionLoader) LoadDefinitionsFromRPC(orgId string) []APISpec {
	var APISpecs = []APISpec{}

	store := RPCStorageHandler{UserKey: config.SlaveOptions.APIKey, Address: config.SlaveOptions.ConnectionString}
	store.Connect()

	apiCollection := store.GetApiDefinitions(orgId)

	store.Disconnect()

	var APIDefinitions = []tykcommon.APIDefinition{}
	var StringDefs = make([]map[string]interface{}, 0)

	jErr1 := json.Unmarshal([]byte(apiCollection), &APIDefinitions)

	if jErr1 != nil {
		log.Error("Failed decode: ", jErr1)
		return APISpecs
	}

	jErr2 := json.Unmarshal([]byte(apiCollection), &StringDefs)
	if jErr2 != nil {
		log.Error("Failed decode: ", jErr2)
		return APISpecs
	}

	for i, thisAppConfig := range APIDefinitions {
		thisAppConfig.DecodeFromDB()
		thisAppConfig.RawData = StringDefs[i] // Lets keep a copy for plugable modules

		newAppSpec := a.MakeSpec(thisAppConfig)
		APISpecs = append(APISpecs, newAppSpec)
	}
	return APISpecs
}

func (a *APIDefinitionLoader) ParseDefinition(apiDef []byte) (tykcommon.APIDefinition, map[string]interface{}) {
	thisAppConfig := tykcommon.APIDefinition{}
	err := json.Unmarshal(apiDef, &thisAppConfig)
	if err != nil {
		log.Error("Couldn't unmarshal api configuration")
		log.Error(err)
	}

	// Got the structured version - now lets get a raw copy for modules
	thisRawConfig := make(map[string]interface{})
	json.Unmarshal(apiDef, &thisRawConfig)

	return thisAppConfig, thisRawConfig
}

// LoadDefinitions will load APIDefinitions from a directory on the filesystem. Definitions need
// to be the JSON representation of APIDefinition object
func (a *APIDefinitionLoader) LoadDefinitions(dir string) []APISpec {
	var APISpecs = []APISpec{}
	// Grab json files from directory
	files, _ := ioutil.ReadDir(dir)
	for _, f := range files {
		if strings.Contains(f.Name(), ".json") {
			filePath := filepath.Join(dir, f.Name())
			log.Info("Loading API Specification from ", filePath)
			appConfig, err := ioutil.ReadFile(filePath)
			thisAppConfig, thisRawConfig := a.ParseDefinition(appConfig)
			if err != nil {
				log.Error("Couldn't load app configuration file")
				log.Error(err)
			}

			thisAppConfig.RawData = thisRawConfig // Lets keep a copy for plugable modules
			newAppSpec := a.MakeSpec(thisAppConfig)
			APISpecs = append(APISpecs, newAppSpec)

		}
	}

	return APISpecs
}

func (a *APIDefinitionLoader) getPathSpecs(apiVersionDef tykcommon.VersionInfo) ([]URLSpec, bool) {
	ignoredPaths := a.compilePathSpec(apiVersionDef.Paths.Ignored, Ignored)
	blackListPaths := a.compilePathSpec(apiVersionDef.Paths.BlackList, BlackList)
	whiteListPaths := a.compilePathSpec(apiVersionDef.Paths.WhiteList, WhiteList)

	combinedPath := []URLSpec{}
	combinedPath = append(combinedPath, ignoredPaths...)
	combinedPath = append(combinedPath, blackListPaths...)
	combinedPath = append(combinedPath, whiteListPaths...)

	if len(whiteListPaths) > 0 {
		return combinedPath, true
	}

	return combinedPath, false
}

func (a *APIDefinitionLoader) generateRegex(stringSpec string, newSpec *URLSpec, specType URLStatus) {
	apiLangIDsRegex, _ := regexp.Compile("{(.*?)}")
	asRegexStr := apiLangIDsRegex.ReplaceAllString(stringSpec, "(.*?)")
	asRegex, _ := regexp.Compile(asRegexStr)
	newSpec.Status = specType
	newSpec.Spec = asRegex

}

func (a *APIDefinitionLoader) compilePathSpec(paths []string, specType URLStatus) []URLSpec {

	// transform a configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	thisURLSpec := []URLSpec{}

	for _, stringSpec := range paths {
		newSpec := URLSpec{}
		a.generateRegex(stringSpec, &newSpec, specType)
		thisURLSpec = append(thisURLSpec, newSpec)
	}

	return thisURLSpec
}

func (a *APIDefinitionLoader) compileExtendedPathSpec(paths []tykcommon.EndPointMeta, specType URLStatus) []URLSpec {

	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	thisURLSpec := []URLSpec{}

	for _, stringSpec := range paths {
		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, specType)

		// Extend with method actions
		newSpec.MethodActions = stringSpec.MethodActions
		thisURLSpec = append(thisURLSpec, newSpec)
	}

	return thisURLSpec
}

func (a *APIDefinitionLoader) compileCachedPathSpec(paths []string) []URLSpec {

	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	thisURLSpec := []URLSpec{}

	for _, stringSpec := range paths {
		newSpec := URLSpec{}
		a.generateRegex(stringSpec, &newSpec, Cached)
		// Extend with method actions
		thisURLSpec = append(thisURLSpec, newSpec)
	}

	return thisURLSpec
}

func (a *APIDefinitionLoader) loadFileTemplate(path string) (*textTemplate.Template, error) {
	log.Info("-- Loading template: ", path)
	thisT, tErr := textTemplate.ParseFiles(path)

	return thisT, tErr
}

func (a *APIDefinitionLoader) loadBlobTemplate(blob string) (*textTemplate.Template, error) {
	log.Info("-- Loading blob")
	uDec, decErr := b64.StdEncoding.DecodeString(blob)

	if decErr != nil {
		return nil, decErr
	}

	thisT, tErr := textTemplate.New("blob").Parse(string(uDec))
	return thisT, tErr
}

func (a *APIDefinitionLoader) compileTransformPathSpec(paths []tykcommon.TemplateMeta, stat URLStatus) []URLSpec {

	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	thisURLSpec := []URLSpec{}

	log.Debug("Checking for transform paths...")
	for _, stringSpec := range paths {
		log.Info("-- Generating path")
		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat)
		// Extend with template actions

		newTransformSpec := TransformSpec{TemplateMeta: stringSpec}

		// Load the templates
		var templErr error

		switch stringSpec.TemplateData.Mode {
		case tykcommon.UseFile:
			log.Info("-- Using File mode")
			newTransformSpec.Template, templErr = a.loadFileTemplate(stringSpec.TemplateData.TemplateSource)
		case tykcommon.UseBlob:
			log.Info("-- Blob mode")
			newTransformSpec.Template, templErr = a.loadBlobTemplate(stringSpec.TemplateData.TemplateSource)
		default:
			log.Info("-- No mode defined! Found: ", stringSpec.TemplateData.Mode)
			templErr = errors.New("No valid template mode defined, must be either 'file' or 'blob'.")
		}

		if stat == Transformed {
			newSpec.TransformAction = newTransformSpec
		} else {
			newSpec.TransformResponseAction = newTransformSpec
		}

		if templErr == nil {
			thisURLSpec = append(thisURLSpec, newSpec)
			log.Info("-- Loaded")
		} else {
			log.Error("Template load failure! Skipping transformation: ", templErr)
		}

	}

	return thisURLSpec
}

func (a *APIDefinitionLoader) compileInjectedHeaderSpec(paths []tykcommon.HeaderInjectionMeta, stat URLStatus) []URLSpec {

	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	thisURLSpec := []URLSpec{}

	for _, stringSpec := range paths {
		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat)
		// Extend with method actions
		if stat == HeaderInjected {
			newSpec.InjectHeaders = stringSpec
		} else {
			newSpec.InjectHeadersResponse = stringSpec
		}

		thisURLSpec = append(thisURLSpec, newSpec)
	}

	return thisURLSpec
}

func (a *APIDefinitionLoader) compileTimeoutPathSpec(paths []tykcommon.HardTimeoutMeta, stat URLStatus) []URLSpec {

	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	thisURLSpec := []URLSpec{}

	for _, stringSpec := range paths {
		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat)
		// Extend with method actions
		newSpec.HardTimeout = stringSpec

		thisURLSpec = append(thisURLSpec, newSpec)
	}

	return thisURLSpec
}

func (a *APIDefinitionLoader) compileCircuitBreakerPathSpec(paths []tykcommon.CircuitBreakerMeta, stat URLStatus, apiSpec *APISpec) []URLSpec {

	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	thisURLSpec := []URLSpec{}

	for _, stringSpec := range paths {
		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat)
		// Extend with method actions
		newSpec.CircuitBreaker = ExtendedCircuitBreakerMeta{CircuitBreakerMeta: stringSpec}
		log.Debug("Initialising circuit breaker for: ", stringSpec.Path)
		newSpec.CircuitBreaker.CB = circuit.NewRateBreaker(stringSpec.ThresholdPercent, stringSpec.Samples)
		events := newSpec.CircuitBreaker.CB.Subscribe()
		go func() {
			path := stringSpec.Path
			spec := apiSpec
			breakerPtr := newSpec.CircuitBreaker.CB
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

					spec.FireEvent(EVENT_BreakerTriggered,
						EVENT_CurcuitBreakerMeta{
							EventMetaDefault: EventMetaDefault{Message: "Breaker Tripped"},
							CircuitEvent:     e,
							Path:             path,
							APIID:            spec.APIID,
						})

				case circuit.BreakerReset:
					spec.FireEvent(EVENT_BreakerTriggered,
						EVENT_CurcuitBreakerMeta{
							EventMetaDefault: EventMetaDefault{Message: "Breaker Reset"},
							CircuitEvent:     e,
							Path:             path,
							APIID:            spec.APIID,
						})

				}
			}
		}()

		thisURLSpec = append(thisURLSpec, newSpec)
	}

	return thisURLSpec
}

func (a *APIDefinitionLoader) compileURLRewritesPathSpec(paths []tykcommon.URLRewriteMeta, stat URLStatus) []URLSpec {

	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	thisURLSpec := []URLSpec{}

	for _, stringSpec := range paths {
		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat)
		// Extend with method actions
		newSpec.URLRewrite = stringSpec

		thisURLSpec = append(thisURLSpec, newSpec)
	}

	return thisURLSpec
}

func (a *APIDefinitionLoader) getExtendedPathSpecs(apiVersionDef tykcommon.VersionInfo, apiSpec *APISpec) ([]URLSpec, bool) {
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

	log.Info(urlRewrites)

	if len(whiteListPaths) > 0 {
		return combinedPath, true
	}

	return combinedPath, false
}

func (a *APISpec) Init(AuthStore StorageHandler, SessionStore StorageHandler, healthStorageHandler StorageHandler, orgStorageHandler StorageHandler) {
	a.AuthManager.Init(AuthStore)
	a.SessionManager.Init(SessionStore)
	a.Health.Init(healthStorageHandler)
	a.OrgSessionManager.Init(orgStorageHandler)
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
	default:
		log.Error("URL Status was not one of Ignored, Blacklist or WhiteList! Blocking.")
		return EndPointNotAllowed
	}
}

// IsURLAllowedAndIgnored checks if a url is allowed and ignored.
func (a *APISpec) IsURLAllowedAndIgnored(method, url string, RxPaths *[]URLSpec, WhiteListStatus bool) (RequestStatus, interface{}) {
	// Check if ignored
	for _, v := range *RxPaths {
		match := v.Spec.MatchString(url)
		if match {
			if v.MethodActions != nil {
				// We are using an extended path set, check for the method
				methodMeta, matchMethodOk := v.MethodActions[method]
				if matchMethodOk {
					// Matched the method, check what status it is:
					if methodMeta.Action != tykcommon.NoAction {
						// TODO: Extend here for additional reply options
						switch methodMeta.Action {
						case tykcommon.Reply:
							return StatusRedirectFlowByReply, &methodMeta
						default:
							log.Error("URL Method Action was not set to NoAction, blocking.")
							return EndPointNotAllowed, nil
						}
					}

					// NoAction status means we're not treating this request in any special or exceptional way
					return a.getURLStatus(v.Status), nil

				}

				if WhiteListStatus {
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
	}

	// Nothing matched - should we still let it through?
	if WhiteListStatus {
		// We have a whitelist, nothing gets through unless specifically defined
		return EndPointNotAllowed, nil
	}

	// No whitelist, but also not in any of the other lists, let it through and filter
	return StatusOk, nil

}

// CheckSpecMatchesStatus checks if a url spec has a specific status
func (a *APISpec) CheckSpecMatchesStatus(url string, method interface{}, RxPaths *[]URLSpec, mode URLStatus) (bool, interface{}) {
	// Check if ignored
	for _, v := range *RxPaths {
		match := v.Spec.MatchString(url)
		if match {
			// only return it it's what we are looking for
			if mode == v.Status {
				switch v.Status {
				case Ignored:
					return true, nil
				case BlackList:
					return true, nil
				case WhiteList:
					return true, nil
				case Cached:
					return true, nil
				case Transformed:
					if method != nil && method.(string) == v.TransformAction.TemplateMeta.Method {
						return true, &v.TransformAction
					}
				case HeaderInjected:
					if method != nil && method.(string) == v.InjectHeaders.Method {
						return true, &v.InjectHeaders
					}
				case HeaderInjectedResponse:
					if method != nil && method.(string) == v.InjectHeadersResponse.Method {
						return true, &v.InjectHeadersResponse
					}
				case TransformedResponse:
					if method != nil && method.(string) == v.TransformResponseAction.TemplateMeta.Method {
						return true, &v.TransformResponseAction
					}
				case HardTimeout:
					if method != nil && method.(string) == v.HardTimeout.Method {
						return true, &v.HardTimeout.TimeOut
					}
				case CircuitBreaker:
					if method != nil && method.(string) == v.CircuitBreaker.Method {
						return true, &v.CircuitBreaker
					}
				case URLRewrite:
					if method != nil && method.(string) == v.URLRewrite.Method {
						return true, &v.URLRewrite
					}
				}

			}
		}
	}
	return false, nil
}

func (a *APISpec) getVersionFromRequest(r *http.Request) string {
	if a.APIDefinition.VersionDefinition.Location == "header" {
		versionHeaderVal := r.Header.Get(a.APIDefinition.VersionDefinition.Key)
		if versionHeaderVal != "" {
			return versionHeaderVal
		}

		return ""

	} else if a.APIDefinition.VersionDefinition.Location == "url-param" {
		tempRes := CopyRequest(r)
		fromParam := tempRes.FormValue(a.APIDefinition.VersionDefinition.Key)
		if fromParam != "" {
			return fromParam
		}

		return ""

	} else {
		return ""
	}

	return ""
}

// IsThisAPIVersionExpired checks if an API version (during a proxied request) is expired
func (a *APISpec) IsThisAPIVersionExpired(versionDef *tykcommon.VersionInfo) bool {
	// Never expires
	if versionDef.Expires == "-1" {
		return false
	}

	if versionDef.Expires == "" {
		return false
	}

	// otherwise - calculate the time
	t, err := time.Parse("2006-01-02 15:04", versionDef.Expires)
	if err != nil {
		log.Error("Could not parse expiry date for API, dissallow")
		log.Error(err)
		return true
	}

	remaining := time.Since(t)
	if remaining < 0 {
		// It's in the future, keep going
		return false
	}

	// It's in the past, expire
	return true

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
	if a.IsThisAPIVersionExpired(versionMetaData) == true {
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
	default:
		return true, StatusOk, meta
	}

}

// GetVersionData attempts to extract the version data from a request, depending on where it is stored in the
// request (currently only "header" is supported)
func (a *APISpec) GetVersionData(r *http.Request) (*tykcommon.VersionInfo, *[]URLSpec, bool, RequestStatus) {
	var thisVersion = tykcommon.VersionInfo{}
	var versionKey string
	var versionRxPaths = []URLSpec{}
	var versionWLStatus bool

	// try the context first
	aVersion, foundInContext := context.GetOk(r, VersionData)

	if foundInContext {
		thisVersion = aVersion.(tykcommon.VersionInfo)
		versionKey = context.Get(r, VersionKeyContext).(string)
	} else {
		// Are we versioned?
		if a.APIDefinition.VersionData.NotVersioned {
			// Get the first one in the list
			for k, v := range a.APIDefinition.VersionData.Versions {
				versionKey = k
				thisVersion = v
				break
			}
		} else {
			// Extract Version Info
			versionKey = a.getVersionFromRequest(r)
			if versionKey == "" {
				return &thisVersion, &versionRxPaths, versionWLStatus, VersionNotFound
			}
		}

		// Load Version Data - General
		var ok bool
		thisVersion, ok = a.APIDefinition.VersionData.Versions[versionKey]
		if !ok {
			return &thisVersion, &versionRxPaths, versionWLStatus, VersionDoesNotExist
		}

		// Lets save this for the future
		context.Set(r, VersionData, thisVersion)
		context.Set(r, VersionKeyContext, versionKey)
	}

	// Load path data and whitelist data for version
	RxPaths, rxOk := a.RxPaths[versionKey]
	WhiteListStatus, wlOk := a.WhiteListEnabled[versionKey]

	if !rxOk {
		log.Error("no RX Paths found for version")
		log.Error(versionKey)
		return &thisVersion, &versionRxPaths, versionWLStatus, VersionDoesNotExist
	}

	if !wlOk {
		log.Error("No whitelist data found")
		return &thisVersion, &versionRxPaths, versionWLStatus, VersionWhiteListStatusNotFound
	}

	versionRxPaths = RxPaths
	versionWLStatus = WhiteListStatus

	return &thisVersion, &versionRxPaths, versionWLStatus, StatusOk

}

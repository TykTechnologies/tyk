package main

import (
	"encoding/json"
//	"github.com/RangelReale/osin"
	"io/ioutil"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"github.com/lonelycode/tykcommon"
)

//type AuthProviderCode string
//type SessionProviderCode string
//type StorageEngineCode string
//
const (
	DefaultAuthProvider tykcommon.AuthProviderCode = "default"
	DefaultSessionProvider tykcommon.SessionProviderCode = "default"
	DefaultStorageEngine tykcommon.StorageEngineCode = "redis"
)
//
//type AuthProviderMeta struct {
//	Name AuthProviderCode	`bson:"name" json:"name"`
//	StorageEngine StorageEngineCode `bson:"storage_engine" json:"storage_engine"`
//	Meta interface{}		`bson:"meta" json:"meta"`
//}
//
//type SessionProviderMeta struct {
//	Name SessionProviderCode	`bson:"name" json:"name"`
//	StorageEngine StorageEngineCode `bson:"storage_engine" json:"storage_engine"`
//	Meta interface{}			`bson:"meta" json:"meta"`
//}
//
//type EventHandlerTriggerConfig struct {
//	Handler TykEventHandlerName	`bson:"handler_name" json:"handler_name"`
//	HandlerMeta interface{} `bson:"handler_meta" json:"handler_meta"`
//}
//
//type EventHandlerMetaConfig struct {
//	Events map[TykEvent][]EventHandlerTriggerConfig `bson:"events" json:"events"`
//}
//
//// APIDefinition represents the configuration for a single proxied API and it's versions.
//type APIDefinition struct {
//	ID               bson.ObjectId `bson:"_id,omitempty" json:"id"`
//	Name             string        `bson:"name" json:"name"`
//	APIID            string        `bson:"api_id" json:"api_id"`
//	OrgID            string        `bson:"org_id" json:"org_id"`
//	UseKeylessAccess bool          `bson:"use_keyless" json:"use_keyless"`
//	UseOauth2        bool          `bson:"use_oauth2" json:"use_oauth2"`
//	Oauth2Meta       struct {
//		AllowedAccessTypes     []osin.AccessRequestType    `bson:"allowed_access_types" json:"allowed_access_types"`
//		AllowedAuthorizeTypes  []osin.AuthorizeRequestType `bson:"allowed_authorize_types" json:"allowed_authorize_types"`
//		AuthorizeLoginRedirect string                      `bson:"auth_login_redirect" json:"auth_login_redirect"`
//	} `bson:"oauth_meta" json:"oauth_meta"`
//	UseBasicAuth            bool                 `bson:"use_basic_auth" json:"use_basic_auth"`
//	NotificationsDetails    NotificationsManager `bson:"notifications" json:"notifications"`
//	EnableSignatureChecking bool                 `bson:"enable_signature_checking" json:"enable_signature_checking"`
//	VersionDefinition       struct {
//		Location string `bson:"location" json:"location"`
//		Key      string `bson:"key" json:"key"`
//	} `bson:"definition" json:"definition"`
//	VersionData struct {
//		NotVersioned bool                   `bson:"not_versioned" json:"not_versioned"`
//		Versions     map[string]VersionInfo `bson:"versions" json:"versions"`
//	} `bson:"version_data" json:"version_data"`
//	Proxy struct {
//		ListenPath      string `bson:"listen_path" json:"listen_path"`
//		TargetURL       string `bson:"target_url" json:"target_url"`
//		StripListenPath bool   `bson:"strip_listen_path" json:"strip_listen_path"`
//	} `bson:"proxy" json:"proxy"`
//	SessionLifetime int64 `bson:"session_lifetime" json:"session_lifetime"`
//	Active  bool                   `bson:"active" json:"active"`
//	AuthProvider AuthProviderMeta	`bson:"auth_provider" json:"auth_provider"`
//	SessionProvider SessionProviderMeta	`bson:"session_provider" json:"session_provider"`
//	EventHandlers EventHandlerMetaConfig `bson:"event_handlers" json:"event_handlers"`
//	EnableBatchRequestSupport bool	`bson:"enable_batch_request_support" json:"enable_batch_request_support"`
//	RawData map[string]interface{} `bson:"raw_data,omitempty" json:"raw_data,omitempty"` // Not used in actual configuration, loaded by config for plugable arc
//}
//
//// VersionInfo encapsulates all the data for a specific api_version, elements in the
//// Paths array are checked as part of the proxy routing.
//type VersionInfo struct {
//	Name    string `bson:"name" json:"name"`
//	Expires string `bson:"expires" json:"expires"`
//	Paths   struct {
//		Ignored   []string `bson:"ignored" json:"ignored"`
//		WhiteList []string `bson:"white_list" json:"white_list"`
//		BlackList []string `bson:"black_list" json:"black_list"`
//	} `bson:"paths" json:"paths"`
//}

// URLStatus is a custom enum type to avoid collisions
type URLStatus int

// Enums representing the various statuses for a VersionInfo Path match during a
// proxy request
const (
	Ignored   URLStatus = 1
	WhiteList URLStatus = 2
	BlackList URLStatus = 3
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
)

// URLSpec represents a flattened specification for URLs, used to check if a proxy URL
// path is on any of the white, plack or ignored lists. This is generated as part of the
// configuration init
type URLSpec struct {
	Spec   *regexp.Regexp
	Status URLStatus
}

// APISpec represents a path specification for an API, to avoid enumerating multiple nested lists, a single
// flattened URL list is checked for matching paths and then it's status evaluated if found.
type APISpec struct {
	tykcommon.APIDefinition
	RxPaths          map[string][]URLSpec
	WhiteListEnabled map[string]bool
	target           *url.URL
	AuthManager AuthorisationHandler
	SessionManager SessionHandler
	OAuthManager *OAuthManager
	EventPaths map[tykcommon.TykEvent][]TykEventHandler
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

	// Add any new session managers or auth handlers here
	if newAppSpec.APIDefinition.AuthProvider.Name != "" {
		switch newAppSpec.APIDefinition.AuthProvider.Name {
			case DefaultAuthProvider: newAppSpec.AuthManager = &DefaultAuthorisationManager{}
			default: newAppSpec.AuthManager = &DefaultAuthorisationManager{}
		}
	} else {
		newAppSpec.AuthManager = &DefaultAuthorisationManager{}
	}

	if newAppSpec.APIDefinition.SessionProvider.Name != "" {
		switch newAppSpec.APIDefinition.SessionProvider.Name {
			case DefaultSessionProvider: newAppSpec.SessionManager = &DefaultSessionManager{}
			default: newAppSpec.SessionManager = &DefaultSessionManager{}
		}
	} else {
		newAppSpec.SessionManager = &DefaultSessionManager{}
	}

	// Set up Event Handlers
	log.Debug("INITIALISING EVENT HANDLERS")
	newAppSpec.EventPaths = make(map[tykcommon.TykEvent][]TykEventHandler)
	for eventName, eventHandlerConfs := range(thisAppConfig.EventHandlers.Events) {
		log.Debug("FOUND EVENTS TO INIT")
		for _, handlerConf := range(eventHandlerConfs) {
			log.Debug("CREATING EVENT HANDLERS")
			thisEventHandlerInstance, getHandlerErr := GetEventHandlerByName(handlerConf)

			if getHandlerErr != nil {
				log.Error("Failed to init event handler: ", getHandlerErr)
			} else {
				log.Info("Init Event Handler: ", eventName)
				newAppSpec.EventPaths[eventName] = append(newAppSpec.EventPaths[eventName], thisEventHandlerInstance)
			}

		}
	}


	newAppSpec.RxPaths = make(map[string][]URLSpec)
	newAppSpec.WhiteListEnabled = make(map[string]bool)
	for _, v := range thisAppConfig.VersionData.Versions {
		pathSpecs, whiteListSpecs := a.getPathSpecs(v)
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
		log.Error("Could not find any application configs!")
		return APISpecs
	}

	apiCollection.Find(search).All(&StringDefs)

	for i, thisAppConfig := range APIDefinitions {
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

func (a *APIDefinitionLoader) compilePathSpec(paths []string, specType URLStatus) []URLSpec {

	// transform a configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	apiLangIDsRegex, _ := regexp.Compile("{(.*?)}")
	thisURLSpec := []URLSpec{}

	for _, stringSpec := range paths {
		asRegexStr := apiLangIDsRegex.ReplaceAllString(stringSpec, "(.*?)")
		asRegex, _ := regexp.Compile(asRegexStr)

		newSpec := URLSpec{}
		newSpec.Spec = asRegex
		newSpec.Status = specType
		thisURLSpec = append(thisURLSpec, newSpec)
	}

	return thisURLSpec
}

func (a *APISpec) Init(AuthStore StorageHandler, SessionStore StorageHandler) {
	a.AuthManager.Init(AuthStore)
	a.SessionManager.Init(SessionStore)
}

// IsURLAllowedAndIgnored checks if a url is allowed and ignored.
func (a *APISpec) IsURLAllowedAndIgnored(url string, RxPaths []URLSpec, WhiteListStatus bool) (bool, bool) {
	// Check if ignored
	for _, v := range RxPaths {
		match := v.Spec.MatchString(url)
		if match {
			if v.Status == Ignored {
				// Let it pass, and do not check auth
				return true, true
			} else if v.Status == BlackList {
				// Matched  a blacklist URL, disallow access and filter (irrelevant here)
				return false, false
			} else if v.Status == WhiteList {
				// Matched whitelist, allow request but filter
				return true, false
			}

			// Should not occur, something has gone wrong
			log.Error("URL Status was not one of Ignored, Blacklist or WhiteList! Blocking.")
			return false, false

		}
	}

	// Nothing matched - should we still let it through?
	if WhiteListStatus {
		// We have a whitelist, nothing gets through unless specifically defined
		return false, false
	}

	// No whitelist, but also not in any of the other lists, let it through and filter
	return true, false

}

func (a *APISpec) getVersionFromRequest(r *http.Request) string {
	if a.APIDefinition.VersionDefinition.Location == "header" {
		versionHeaderVal := r.Header.Get(a.APIDefinition.VersionDefinition.Key)
		if versionHeaderVal != "" {
			return versionHeaderVal
		}

		return ""

	} else if a.APIDefinition.VersionDefinition.Location == "url-param" {
		fromParam := r.FormValue(a.APIDefinition.VersionDefinition.Key)
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
func (a *APISpec) IsThisAPIVersionExpired(versionDef tykcommon.VersionInfo) bool {
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
func (a *APISpec) IsRequestValid(r *http.Request) (bool, RequestStatus) {
	versionMetaData, versionPaths, whiteListStatus, stat := a.GetVersionData(r)

	// Screwed up version info - fail and pass through
	if stat != StatusOk {
		return false, stat
	}

	// Is the API version expired?
	if a.IsThisAPIVersionExpired(versionMetaData) == true {
		// Expired - fail
		return false, VersionExpired
	}

	// not expired, let's check path info
	allowURL, ignore := a.IsURLAllowedAndIgnored(r.URL.Path, versionPaths, whiteListStatus)
	if !allowURL {
		return false, EndPointNotAllowed
	}

	if ignore {
		return true, StatusOkAndIgnore
	}

	return true, StatusOk

}

// GetVersionData attempts to extract the version data from a request, depending on where it is stored in the
// request (currently only "header" is supported)
func (a *APISpec) GetVersionData(r *http.Request) (tykcommon.VersionInfo, []URLSpec, bool, RequestStatus) {
	var thisVersion = tykcommon.VersionInfo{}
	var versionKey string
	var versionRxPaths = []URLSpec{}
	var versionWLStatus bool

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
			return thisVersion, versionRxPaths, versionWLStatus, VersionNotFound
		}
	}

	// Load Version Data - General
	var ok bool
	thisVersion, ok = a.APIDefinition.VersionData.Versions[versionKey]
	if !ok {
		return thisVersion, versionRxPaths, versionWLStatus, VersionDoesNotExist
	}

	// Load path data and whitelist data for version
	RxPaths, rxOk := a.RxPaths[versionKey]
	WhiteListStatus, wlOk := a.WhiteListEnabled[versionKey]

	if !rxOk {
		log.Error("no RX Paths found for version")
		log.Error(versionKey)
		return thisVersion, versionRxPaths, versionWLStatus, VersionDoesNotExist
	}

	if !wlOk {
		log.Error("No whitelist data found")
		return thisVersion, versionRxPaths, versionWLStatus, VersionWhiteListStatusNotFound
	}

	versionRxPaths = RxPaths
	versionWLStatus = WhiteListStatus

	return thisVersion, versionRxPaths, versionWLStatus, StatusOk

}

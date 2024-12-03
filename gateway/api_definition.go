package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	texttemplate "text/template"
	"time"

	"github.com/TykTechnologies/tyk/ee/middleware/streams"
	"github.com/TykTechnologies/tyk/storage/kv"

	"github.com/TykTechnologies/tyk/internal/httputil"

	"github.com/getkin/kin-openapi/routers/gorillamux"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef/oas"

	"github.com/cenk/backoff"

	"github.com/Masterminds/sprig/v3"

	"github.com/sirupsen/logrus"

	circuit "github.com/TykTechnologies/circuitbreaker"

	"github.com/TykTechnologies/gojsonschema"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/regexp"
	"github.com/TykTechnologies/tyk/rpc"
	"github.com/TykTechnologies/tyk/storage"
)

// const used by cache middleware
const SAFE_METHODS = "SAFE_METHODS"

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
	MockResponse
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
	GoPlugin
	PersistGraphQL
	RateLimit
)

// RequestStatus is a custom type to avoid collisions
type RequestStatus string

// Statuses of the request, all are false-y except StatusOk and StatusOkAndIgnore
const (
	VersionNotFound                RequestStatus = "Version information not found"
	VersionDoesNotExist            RequestStatus = "This API version does not seem to exist"
	VersionWhiteListStatusNotFound RequestStatus = "WhiteListStatus for path not found"
	VersionExpired                 RequestStatus = "Api Version has expired, please check documentation or contact administrator"
	APIExpired                     RequestStatus = "API has expired, please check documentation or contact administrator"
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
	StatusValidateRequest          RequestStatus = "Validate Request"
	StatusInternal                 RequestStatus = "Internal path"
	StatusGoPlugin                 RequestStatus = "Go plugin"
	StatusPersistGraphQL           RequestStatus = "Persist GraphQL"
	StatusRateLimit                RequestStatus = "Rate Limited"
)

type EndPointCacheMeta struct {
	Method                 string
	CacheKeyRegex          string
	CacheOnlyResponseCodes []int
	Timeout                int64
}

type TransformSpec struct {
	apidef.TemplateMeta
	Template *texttemplate.Template
}

type ExtendedCircuitBreakerMeta struct {
	apidef.CircuitBreakerMeta
	CB *circuit.Breaker `json:"-"`
}

type OAuthManagerInterface interface {
	Storage() ExtendedOsinStorageInterface
}

// GetSessionLifetimeRespectsKeyExpiration returns a boolean to tell whether session lifetime should respect to key expiration or not.
// The global config takes the precedence. If the global one is `true`, value of the one in api level doesn't matter.
func (a *APISpec) GetSessionLifetimeRespectsKeyExpiration() bool {
	if a.GlobalConfig.SessionLifetimeRespectsKeyExpiration {
		return true
	}

	return a.SessionLifetimeRespectsKeyExpiration
}

// AddUnloadHook adds a function to be called when the API spec is unloaded
func (s *APISpec) AddUnloadHook(hook func()) {
	s.unloadHooks = append(s.unloadHooks, hook)
}

// Release releases all resources associated with API spec
func (s *APISpec) Unload() {
	s.Lock()
	defer s.Unlock()

	// release circuit breaker resources
	for _, path := range s.RxPaths {
		for _, urlSpec := range path {
			if urlSpec.CircuitBreaker.CB != nil {
				// this will force CB-event reading Go-routine and subscriber Go-routine to exit
				urlSpec.CircuitBreaker.CB.Stop()
			}
		}
	}

	// cancel execution contexts
	if s.GraphEngine != nil {
		s.GraphEngine.Cancel()
	}

	// release all other resources associated with spec

	// JSVM object is a circular dependecy hell, but we can check if it initialized like this
	if s.JSVM.VM != nil {
		s.JSVM.DeInit()
	}

	if s.HTTPTransport != nil {
		// Prevent new idle connections to be generated.
		s.HTTPTransport.transport.DisableKeepAlives = true
		s.HTTPTransport.transport.CloseIdleConnections()
		s.HTTPTransport = nil
	}

	for _, hook := range s.unloadHooks {
		hook()
	}
	s.unloadHooks = nil
}

// Validate returns nil if s is a valid spec and an error stating why the spec is not valid.
func (s *APISpec) Validate(oasConfig config.OASConfig) error {
	if s.IsOAS {
		err := s.OAS.Validate(context.Background(), oas.GetValidationOptionsFromConfig(oasConfig)...)
		if err != nil {
			return err
		}
	}

	// For tcp services we need to make sure we can bind to the port.
	switch s.Protocol {
	case "tcp", "tls":
		return s.validateTCP()
	default:
		return s.validateHTTP()
	}
}

func (s *APISpec) validateTCP() error {
	if s.ListenPort == 0 {
		return errors.New("missing listening port")
	}
	return nil
}

func (s *APISpec) validateHTTP() error {
	// NOOP
	return nil
}

func (s *APISpec) isStreamingAPI() bool {
	if s.OAS.T.Extensions == nil {
		return false
	}

	_, ok := s.OAS.T.Extensions[streams.ExtensionTykStreaming]
	return ok
}

// APIDefinitionLoader will load an Api definition from a storage
// system.
type APIDefinitionLoader struct {
	Gw *Gateway `json:"-"`
}

// MakeSpec will generate a flattened URLSpec from and APIDefinitions' VersionInfo data. paths are
// keyed to the Api version name, which is determined during routing to speed up lookups
func (a APIDefinitionLoader) MakeSpec(def *model.MergedAPI, logger *logrus.Entry) (*APISpec, error) {
	spec := &APISpec{}
	apiString, err := json.Marshal(def)
	if err != nil {
		logger.WithError(err).WithField("name", def.Name).Error("Failed to JSON marshal API definition")
		return nil, err
	}

	sha256hash := sha256.Sum256(apiString)
	// Unique API content ID, to check if we already have if it changed from previous sync
	spec.Checksum = base64.URLEncoding.EncodeToString(sha256hash[:])

	spec.APIDefinition = def.APIDefinition

	if currSpec := a.Gw.getApiSpec(def.APIID); !shouldReloadSpec(currSpec, spec) {
		return currSpec, nil
	}

	if logger == nil {
		logger = logrus.NewEntry(log)
	}

	// new expiration feature
	if def.Expiration != "" {
		if t, err := time.Parse(apidef.ExpirationTimeFormat, def.Expiration); err != nil {
			logger.WithError(err).WithField("name", def.Name).WithField("Expiration", def.Expiration).
				Error("Could not parse expiration date for API")
		} else {
			def.ExpirationTs = t
		}
	}

	// Deprecated
	// parse version expiration time stamps
	for key, ver := range def.VersionData.Versions {
		if ver.Expires == "" || ver.Expires == "-1" {
			continue
		}
		// calculate the time
		if t, err := time.Parse(apidef.ExpirationTimeFormat, ver.Expires); err != nil {
			logger.WithError(err).WithField("Expires", ver.Expires).Error("Could not parse expiry date for API")
		} else {
			ver.ExpiresTs = t
			def.VersionData.Versions[key] = ver
		}
	}

	// We'll push the default HealthChecker:
	spec.Health = &DefaultHealthChecker{
		Gw:    a.Gw,
		APIID: spec.APIID,
	}

	// Add any new session managers or auth handlers here
	spec.AuthManager = &DefaultSessionManager{Gw: a.Gw}
	spec.OrgSessionManager = &DefaultSessionManager{
		orgID: spec.OrgID,
		Gw:    a.Gw,
	}

	spec.GlobalConfig = a.Gw.GetConfig()

	if err = a.Gw.loadBundle(spec); err != nil {
		logger.WithError(err).Error("Couldn't load bundle")
		return nil, err
	}

	if a.Gw.GetConfig().EnableJSVM && (spec.hasVirtualEndpoint() || spec.CustomMiddleware.Driver == apidef.OttoDriver) {
		logger.Debug("Initializing JSVM")
		spec.JSVM.Init(spec, logger, a.Gw)
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
			eventHandlerInstance, err := a.Gw.EventHandlerByName(handlerConf, spec)

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
			pathSpecs, whiteListSpecs = a.getExtendedPathSpecs(v, spec, a.Gw.GetConfig())
		} else {
			logger.Warning("Legacy path detected! Upgrade to extended.")
			pathSpecs, whiteListSpecs = a.getPathSpecs(v, a.Gw.GetConfig())
		}
		spec.RxPaths[v.Name] = pathSpecs
		spec.WhiteListEnabled[v.Name] = whiteListSpecs
	}

	if spec.IsOAS && def.OAS != nil {
		loader := openapi3.NewLoader()
		if err := loader.ResolveRefsIn(&def.OAS.T, nil); err != nil {
			log.WithError(err).Errorf("Dashboard loaded API's OAS reference resolve failed: %s", def.APIID)
		}

		spec.OAS = *def.OAS
	}

	oasSpec := spec.OAS.T
	oasSpec.Servers = openapi3.Servers{
		{URL: spec.Proxy.ListenPath},
	}

	spec.OASRouter, err = gorillamux.NewRouter(&oasSpec)
	if err != nil {
		log.WithError(err).Error("Could not create OAS router")
	}

	spec.setHasMock()

	return spec, nil
}

// FromDashboardService will connect and download ApiDefintions from a Tyk Dashboard instance.
func (a APIDefinitionLoader) FromDashboardService(endpoint string) ([]*APISpec, error) {
	// Get the definitions
	log.Debug("Calling: ", endpoint)
	newRequest, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		log.Error("Failed to create request: ", err)
	}

	gwConfig := a.Gw.GetConfig()

	newRequest.Header.Set("authorization", gwConfig.NodeSecret)
	log.Debug("Using: NodeID: ", a.Gw.GetNodeID())
	newRequest.Header.Set(header.XTykNodeID, a.Gw.GetNodeID())

	a.Gw.ServiceNonceMutex.RLock()
	newRequest.Header.Set(header.XTykNonce, a.Gw.ServiceNonce)
	a.Gw.ServiceNonceMutex.RUnlock()

	c := a.Gw.initialiseClient()
	resp, err := c.Do(newRequest)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		body, _ := ioutil.ReadAll(resp.Body)
		a.Gw.reLogin()
		return nil, fmt.Errorf("login failure, Response was: %v", string(body))
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		a.Gw.reLogin()
		return nil, fmt.Errorf("dashboard API error, response was: %v", string(body))
	}

	// Extract tagged APIs#
	list := model.NewMergedAPIList()
	inBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error("Couldn't read api definition list")
		return nil, err
	}

	inBytes = a.replaceSecrets(inBytes)

	err = json.Unmarshal(inBytes, &list)
	if err != nil {
		log.Error("Couldn't unmarshal api definition list")
		return nil, err
	}

	// Extract tagged entries only
	apiDefs := list.Filter(gwConfig.DBAppConfOptions.NodeIsSegmented, gwConfig.DBAppConfOptions.Tags...)

	// Process
	specs := a.prepareSpecs(apiDefs, gwConfig, false)

	// Set the nonce
	a.Gw.ServiceNonceMutex.Lock()
	a.Gw.ServiceNonce = list.Nonce
	a.Gw.ServiceNonceMutex.Unlock()
	log.Debug("Loading APIS Finished: Nonce Set: ", list.Nonce)

	return specs, nil
}

var envRegex = regexp.MustCompile(`env://([^"]+)`)

const (
	prefixEnv       = "env://"
	prefixSecrets   = "secrets://"
	prefixConsul    = "consul://"
	prefixVault     = "vault://"
	prefixKeys      = "tyk-apis"
	vaultSecretPath = "secret/data/"
)

func (a APIDefinitionLoader) replaceSecrets(in []byte) []byte {
	input := string(in)

	if strings.Contains(input, prefixEnv) {
		matches := envRegex.FindAllStringSubmatch(input, -1)
		uniqueWords := map[string]bool{}
		for _, m := range matches {
			if uniqueWords[m[0]] {
				continue
			}

			uniqueWords[m[0]] = true
			val := os.Getenv(m[1])
			if val != "" {
				input = strings.Replace(input, m[0], val, -1)
			}
		}
	}

	if strings.Contains(input, prefixSecrets) {
		for k, v := range a.Gw.GetConfig().Secrets {
			input = strings.Replace(input, prefixSecrets+k, v, -1)
		}
	}

	if strings.Contains(input, prefixConsul) {
		if err := a.replaceConsulSecrets(&input); err != nil {
			log.WithError(err).Error("Couldn't replace consul secrets")
		}
	}

	if strings.Contains(input, prefixVault) {
		if err := a.replaceVaultSecrets(&input); err != nil {
			log.WithError(err).Error("Couldn't replace vault secrets")
		}
	}

	return []byte(input)
}

func (a APIDefinitionLoader) replaceConsulSecrets(input *string) error {
	if err := a.Gw.setUpConsul(); err != nil {
		return err
	}

	pairs, _, err := a.Gw.consulKVStore.(*kv.Consul).Store().List(prefixKeys, nil)
	if err != nil {
		return err
	}

	for i := 1; i < len(pairs); i++ {
		key := strings.TrimPrefix(pairs[i].Key, prefixKeys+"/")
		*input = strings.Replace(*input, prefixConsul+key, string(pairs[i].Value), -1)
	}

	return nil
}

func (a APIDefinitionLoader) replaceVaultSecrets(input *string) error {
	if err := a.Gw.setUpVault(); err != nil {
		return err
	}

	secret, err := a.Gw.vaultKVStore.(*kv.Vault).Client().Logical().Read(vaultSecretPath + prefixKeys)
	if err != nil {
		return err
	}

	pairs, ok := secret.Data["data"]
	if !ok {
		return errors.New("no data returned")
	}

	pairsMap, ok := pairs.(map[string]interface{})
	if !ok {
		return errors.New("data is not in the map format")
	}

	for k, v := range pairsMap {
		*input = strings.Replace(*input, prefixVault+k, fmt.Sprintf("%v", v), -1)
	}

	return nil
}

// FromCloud will connect and download ApiDefintions from a Mongo DB instance.
func (a APIDefinitionLoader) FromRPC(store RPCDataLoader, orgId string, gw *Gateway) ([]*APISpec, error) {
	if rpc.IsEmergencyMode() {
		return gw.LoadDefinitionsFromRPCBackup()
	}

	if !store.Connect() {
		return nil, errors.New("Can't connect RPC layer")
	}

	// enable segments
	var tags []string
	if gw.GetConfig().DBAppConfOptions.NodeIsSegmented {
		log.Info("Segmented node, loading: ", gw.GetConfig().DBAppConfOptions.Tags)
		tags = gw.GetConfig().DBAppConfOptions.Tags
	}

	apiCollection := store.GetApiDefinitions(orgId, tags)
	apiCollection = string(a.replaceSecrets([]byte(apiCollection)))

	//store.Disconnect()

	if rpc.LoadCount() > 0 {
		if err := gw.saveRPCDefinitionsBackup(apiCollection); err != nil {
			log.Error(err)
		}
	}

	return a.processRPCDefinitions(apiCollection, gw)
}

func (a APIDefinitionLoader) processRPCDefinitions(apiCollection string, gw *Gateway) ([]*APISpec, error) {
	var payload []model.MergedAPI
	if err := json.Unmarshal([]byte(apiCollection), &payload); err != nil {
		return nil, err
	}

	list := model.NewMergedAPIList(payload...)

	gwConfig := a.Gw.GetConfig()

	// Extract tagged entries only
	apiDefs := list.Filter(gwConfig.DBAppConfOptions.NodeIsSegmented, gwConfig.DBAppConfOptions.Tags...)

	specs := a.prepareSpecs(apiDefs, gwConfig, true)

	return specs, nil
}

func (a APIDefinitionLoader) prepareSpecs(apiDefs []model.MergedAPI, gwConfig config.Config, fromRPC bool) []*APISpec {
	var specs []*APISpec

	for _, def := range apiDefs {
		if fromRPC {
			def.DecodeFromDB()

			if gwConfig.SlaveOptions.BindToSlugsInsteadOfListenPaths {
				newListenPath := "/" + def.Slug //+ "/"
				log.Warning("Binding to ",
					newListenPath,
					" instead of ",
					def.Proxy.ListenPath)

				def.Proxy.ListenPath = newListenPath
			}
		}

		spec, err := a.MakeSpec(&def, nil)
		if err != nil {
			continue
		}

		specs = append(specs, spec)
	}

	return specs
}

func (a APIDefinitionLoader) ParseDefinition(r io.Reader) (api apidef.APIDefinition) {
	if err := json.NewDecoder(r).Decode(&api); err != nil {
		log.Error("Couldn't unmarshal api configuration: ", err)
	}

	return
}

func (a APIDefinitionLoader) ParseOAS(r io.Reader) (oas oas.OAS) {
	if err := json.NewDecoder(r).Decode(&oas); err != nil {
		log.Error("Couldn't unmarshal oas configuration: ", err)
	}

	return
}

func (a APIDefinitionLoader) GetOASFilepath(path string) string {
	return strings.TrimSuffix(path, ".json") + "-oas.json"
}

// FromDir will load APIDefinitions from a directory on the filesystem. Definitions need
// to be the JSON representation of APIDefinition object
func (a APIDefinitionLoader) FromDir(dir string) []*APISpec {
	var specs []*APISpec
	// Grab json files from directory
	paths, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	for _, path := range paths {
		if strings.HasSuffix(path, "-oas.json") {
			continue
		}

		spec, err := a.loadDefFromFilePath(path)

		if err != nil {
			continue
		}

		specs = append(specs, spec)
	}
	return specs
}
func (a APIDefinitionLoader) loadDefFromFilePath(filePath string) (*APISpec, error) {
	log.Info("Loading API Specification from ", filePath)

	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Error("Couldn't read api configuration file: ", err)
		return nil, err
	}

	data = a.replaceSecrets(data)

	var def apidef.APIDefinition
	err = json.Unmarshal(data, &def)
	if err != nil {
		log.Error("Couldn't unmarshal read file: ", err)
		return nil, err
	}

	nestDef := model.MergedAPI{APIDefinition: &def}
	if def.IsOAS {
		loader := openapi3.NewLoader()
		// use openapi3.ReadFromFile as ReadFromURIFunc since the default implementation cache spec based on file path.
		loader.ReadFromURIFunc = openapi3.ReadFromFile
		oasDoc, err := loader.LoadFromFile(a.GetOASFilepath(filePath))
		if err == nil {
			nestDef.OAS = &oas.OAS{T: *oasDoc}
		}
	}

	return a.MakeSpec(&nestDef, nil)
}

func (a APIDefinitionLoader) getPathSpecs(apiVersionDef apidef.VersionInfo, conf config.Config) ([]URLSpec, bool) {
	ignoredPaths := a.compilePathSpec(apiVersionDef.Paths.Ignored, Ignored, conf)
	blackListPaths := a.compilePathSpec(apiVersionDef.Paths.BlackList, BlackList, conf)
	whiteListPaths := a.compilePathSpec(apiVersionDef.Paths.WhiteList, WhiteList, conf)

	combinedPath := []URLSpec{}
	combinedPath = append(combinedPath, ignoredPaths...)
	combinedPath = append(combinedPath, blackListPaths...)
	combinedPath = append(combinedPath, whiteListPaths...)

	return combinedPath, len(whiteListPaths) > 0
}

func (a APIDefinitionLoader) generateRegex(stringSpec string, newSpec *URLSpec, specType URLStatus, conf config.Config) {
	var (
		pattern string
		err     error
	)
	// Hook per-api settings here via newSpec *URLSpec
	isPrefixMatch := conf.HttpServerOptions.EnablePathPrefixMatching
	isSuffixMatch := conf.HttpServerOptions.EnablePathSuffixMatching
	isIgnoreCase := newSpec.IgnoreCase || conf.IgnoreEndpointCase

	pattern = httputil.PreparePathRegexp(stringSpec, isPrefixMatch, isSuffixMatch)

	// Case insensitive match
	if isIgnoreCase {
		pattern = "(?i)" + pattern
	}

	asRegex, err := regexp.Compile(pattern)
	log.WithError(err).Debugf("URLSpec: %s => %s type=%d", stringSpec, pattern, specType)

	newSpec.Status = specType
	newSpec.spec = asRegex
}

func (a APIDefinitionLoader) compilePathSpec(paths []string, specType URLStatus, conf config.Config) []URLSpec {
	// transform a configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	urlSpec := []URLSpec{}

	for _, stringSpec := range paths {
		newSpec := URLSpec{}
		a.generateRegex(stringSpec, &newSpec, specType, conf)
		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) compileExtendedPathSpec(ignoreEndpointCase bool, paths []apidef.EndPointMeta, specType URLStatus, conf config.Config) []URLSpec {
	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	urlSpec := []URLSpec{}

	for _, stringSpec := range paths {
		if stringSpec.Disabled {
			continue
		}

		newSpec := URLSpec{IgnoreCase: stringSpec.IgnoreCase || ignoreEndpointCase}
		a.generateRegex(stringSpec.Path, &newSpec, specType, conf)

		switch specType {
		case WhiteList:
			newSpec.Whitelist = stringSpec
		case BlackList:
			newSpec.Blacklist = stringSpec
		case Ignored:
			newSpec.Ignored = stringSpec
		}

		// Extend with method actions
		newSpec.MethodActions = stringSpec.MethodActions

		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) compileMockResponsePathSpec(ignoreEndpointCase bool, paths []apidef.MockResponseMeta, specType URLStatus, conf config.Config) []URLSpec {
	var urlSpec []URLSpec

	for _, stringSpec := range paths {
		if stringSpec.Disabled {
			continue
		}

		newSpec := URLSpec{IgnoreCase: stringSpec.IgnoreCase || ignoreEndpointCase}
		a.generateRegex(stringSpec.Path, &newSpec, specType, conf)

		newSpec.MockResponse = stringSpec
		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) compileCachedPathSpec(oldpaths []string, newpaths []apidef.CacheMeta, conf config.Config) []URLSpec {
	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	urlSpec := []URLSpec{}

	for _, stringSpec := range oldpaths {
		newSpec := URLSpec{}
		a.generateRegex(stringSpec, &newSpec, Cached, conf)
		newSpec.CacheConfig.Method = SAFE_METHODS
		newSpec.CacheConfig.CacheKeyRegex = ""
		// Extend with method actions
		urlSpec = append(urlSpec, newSpec)
	}

	for _, spec := range newpaths {
		if spec.Disabled {
			continue
		}

		newSpec := URLSpec{}
		a.generateRegex(spec.Path, &newSpec, Cached, conf)
		newSpec.CacheConfig.Method = spec.Method
		newSpec.CacheConfig.CacheKeyRegex = spec.CacheKeyRegex
		newSpec.CacheConfig.CacheOnlyResponseCodes = spec.CacheOnlyResponseCodes
		newSpec.CacheConfig.Timeout = spec.Timeout
		// Extend with method actions
		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) filterSprigFuncs() texttemplate.FuncMap {
	tmp := sprig.GenericFuncMap()
	delete(tmp, "env")
	delete(tmp, "expandenv")

	return texttemplate.FuncMap(tmp)
}

func (a APIDefinitionLoader) loadFileTemplate(path string) (*texttemplate.Template, error) {
	log.Debug("-- Loading template: ", path)
	tmpName := filepath.Base(path)
	return apidef.Template.New(tmpName).Funcs(a.filterSprigFuncs()).ParseFiles(path)
}

func (a APIDefinitionLoader) loadBlobTemplate(blob string) (*texttemplate.Template, error) {
	log.Debug("-- Loading blob")
	uDec, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return nil, err
	}
	return apidef.Template.New("").Funcs(a.filterSprigFuncs()).Parse(string(uDec))
}

func (a APIDefinitionLoader) compileTransformPathSpec(paths []apidef.TemplateMeta, stat URLStatus, conf config.Config) []URLSpec {
	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	urlSpec := []URLSpec{}

	log.Debug("Checking for transform paths...")
	for _, stringSpec := range paths {
		if stringSpec.Disabled {
			continue
		}

		log.Debug("-- Generating path")
		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat, conf)
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

func (a APIDefinitionLoader) compileInjectedHeaderSpec(paths []apidef.HeaderInjectionMeta, stat URLStatus, conf config.Config) []URLSpec {
	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	urlSpec := []URLSpec{}

	for _, stringSpec := range paths {
		if stringSpec.Disabled {
			continue
		}

		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat, conf)
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

func (a APIDefinitionLoader) compileMethodTransformSpec(paths []apidef.MethodTransformMeta, stat URLStatus, conf config.Config) []URLSpec {
	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	urlSpec := []URLSpec{}

	for _, stringSpec := range paths {
		if stringSpec.Disabled {
			continue
		}

		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat, conf)
		newSpec.MethodTransform = stringSpec

		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) compileTimeoutPathSpec(paths []apidef.HardTimeoutMeta, stat URLStatus, conf config.Config) []URLSpec {
	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	urlSpec := []URLSpec{}

	for _, stringSpec := range paths {
		if stringSpec.Disabled {
			continue
		}

		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat, conf)
		// Extend with method actions
		newSpec.HardTimeout = stringSpec

		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) compileRequestSizePathSpec(paths []apidef.RequestSizeMeta, stat URLStatus, conf config.Config) []URLSpec {
	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	urlSpec := []URLSpec{}

	for _, stringSpec := range paths {
		if stringSpec.Disabled {
			continue
		}

		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat, conf)
		// Extend with method actions
		newSpec.RequestSize = stringSpec

		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) compileCircuitBreakerPathSpec(paths []apidef.CircuitBreakerMeta, stat URLStatus, apiSpec *APISpec, conf config.Config) []URLSpec {
	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	urlSpec := []URLSpec{}

	for _, stringSpec := range paths {
		if stringSpec.Disabled {
			continue
		}

		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat, conf)
		// Extend with method actions
		newSpec.CircuitBreaker = ExtendedCircuitBreakerMeta{CircuitBreakerMeta: stringSpec}
		log.Debug("Initialising circuit breaker for: ", stringSpec.Path)
		newSpec.CircuitBreaker.CB = circuit.NewRateBreaker(stringSpec.ThresholdPercent, stringSpec.Samples)

		// override backoff algorithm when is not desired to recheck the upstream before the ReturnToServiceAfter happens
		if stringSpec.DisableHalfOpenState {
			newSpec.CircuitBreaker.CB.BackOff = &backoff.StopBackOff{}
		}

		events := newSpec.CircuitBreaker.CB.Subscribe()
		go func(path string, spec *APISpec, breakerPtr *circuit.Breaker) {
			for e := range events {
				switch e {
				case circuit.BreakerTripped:
					log.Warning("[PROXY] [CIRCUIT BREAKER] Breaker tripped for path: ", path)
					log.Debug("Breaker tripped: ", e)

					go func(timeout int, breaker *circuit.Breaker) {
						log.Debug("-- Sleeping for (s): ", timeout)
						time.Sleep(time.Duration(timeout) * time.Second)
						log.Debug("-- Resetting breaker")
						breaker.Reset()
					}(newSpec.CircuitBreaker.ReturnToServiceAfter, breakerPtr)

					if spec.Proxy.ServiceDiscovery.UseDiscoveryService {
						log.Warning("[PROXY] [CIRCUIT BREAKER] Refreshing host list")
						a.Gw.ServiceCache.Delete(spec.APIID)
					}

					spec.FireEvent(EventBreakerTriggered, EventCurcuitBreakerMeta{
						EventMetaDefault: EventMetaDefault{Message: "Breaker Tripped"},
						CircuitEvent:     e,
						Path:             path,
						APIID:            spec.APIID,
					})

					spec.FireEvent(EventBreakerTripped, EventCurcuitBreakerMeta{
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

					spec.FireEvent(EventBreakerReset, EventCurcuitBreakerMeta{
						EventMetaDefault: EventMetaDefault{Message: "Breaker Reset"},
						CircuitEvent:     e,
						Path:             path,
						APIID:            spec.APIID,
					})

				case circuit.BreakerStop:
					// time to stop this Go-routine
					return
				}
			}
		}(stringSpec.Path, apiSpec, newSpec.CircuitBreaker.CB)

		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) compileURLRewritesPathSpec(paths []apidef.URLRewriteMeta, stat URLStatus, conf config.Config) []URLSpec {
	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	urlSpec := []URLSpec{}

	for _, stringSpec := range paths {
		if stringSpec.Disabled {
			continue
		}

		curStringSpec := stringSpec
		newSpec := URLSpec{}
		a.generateRegex(curStringSpec.Path, &newSpec, stat, conf)
		// Extend with method actions
		newSpec.URLRewrite = &curStringSpec

		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) compileVirtualPathsSpec(paths []apidef.VirtualMeta, stat URLStatus, apiSpec *APISpec, conf config.Config) []URLSpec {
	if !conf.EnableJSVM {
		return nil
	}

	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	urlSpec := []URLSpec{}
	for _, stringSpec := range paths {
		if stringSpec.Disabled {
			continue
		}

		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat, conf)
		// Extend with method actions
		newSpec.VirtualPathSpec = stringSpec

		a.Gw.preLoadVirtualMetaCode(&newSpec.VirtualPathSpec, &apiSpec.JSVM)

		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) compileGopluginPathsSpec(paths []apidef.GoPluginMeta, stat URLStatus, _ *APISpec, conf config.Config) []URLSpec {

	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	var urlSpec []URLSpec

	for _, stringSpec := range paths {
		if stringSpec.Disabled {
			continue
		}

		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat, conf)
		// Extend with method actions
		newSpec.GoPluginMeta.Path = stringSpec.PluginPath
		newSpec.GoPluginMeta.SymbolName = stringSpec.SymbolName
		newSpec.GoPluginMeta.Meta.Method = stringSpec.Method
		newSpec.GoPluginMeta.Meta.Path = stringSpec.Path

		newSpec.GoPluginMeta.loadPlugin()

		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) compilePersistGraphQLPathSpec(paths []apidef.PersistGraphQLMeta, stat URLStatus, apiSpec *APISpec, conf config.Config) []URLSpec {
	// transform an extended configuration URL into an array of URLSpecs
	// This way we can iterate the whole array once, on match we break with status
	urlSpec := []URLSpec{}

	for _, stringSpec := range paths {
		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat, conf)
		// Extend with method actions
		newSpec.PersistGraphQL.Path = stringSpec.Path
		newSpec.PersistGraphQL.Method = stringSpec.Method
		newSpec.PersistGraphQL.Operation = stringSpec.Operation
		newSpec.PersistGraphQL.Variables = stringSpec.Variables

		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) compileTrackedEndpointPathsSpec(paths []apidef.TrackEndpointMeta, stat URLStatus, conf config.Config) []URLSpec {

	urlSpec := []URLSpec{}

	for _, stringSpec := range paths {
		if stringSpec.Disabled {
			continue
		}

		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat, conf)

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

func (a APIDefinitionLoader) compileValidateJSONPathsSpec(paths []apidef.ValidatePathMeta, stat URLStatus, conf config.Config) []URLSpec {
	var urlSpec []URLSpec

	for _, stringSpec := range paths {
		if stringSpec.Disabled {
			continue
		}

		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat, conf)
		// Extend with method actions

		stringSpec.SchemaCache = gojsonschema.NewGoLoader(stringSpec.Schema)
		newSpec.ValidatePathMeta = stringSpec
		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) compileUnTrackedEndpointPathsSpec(paths []apidef.TrackEndpointMeta, stat URLStatus, conf config.Config) []URLSpec {
	urlSpec := []URLSpec{}

	for _, stringSpec := range paths {
		if stringSpec.Disabled {
			continue
		}

		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat, conf)
		// Extend with method actions
		newSpec.DoNotTrackEndpoint = stringSpec
		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) compileInternalPathsSpec(paths []apidef.InternalMeta, stat URLStatus, conf config.Config) []URLSpec {
	urlSpec := []URLSpec{}

	for _, stringSpec := range paths {
		if stringSpec.Disabled {
			continue
		}

		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat, conf)
		// Extend with method actions
		newSpec.Internal = stringSpec
		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) compileRateLimitPathsSpec(paths []apidef.RateLimitMeta, stat URLStatus, conf config.Config) []URLSpec {
	urlSpec := []URLSpec{}

	for _, stringSpec := range paths {
		if stringSpec.Disabled {
			continue
		}

		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat, conf)
		// Extend with method actions
		newSpec.RateLimit = stringSpec
		urlSpec = append(urlSpec, newSpec)
	}

	return urlSpec
}

func (a APIDefinitionLoader) getExtendedPathSpecs(apiVersionDef apidef.VersionInfo, apiSpec *APISpec, conf config.Config) ([]URLSpec, bool) {
	// TODO: New compiler here, needs to put data into a different structure

	mockResponsePaths := a.compileMockResponsePathSpec(apiVersionDef.IgnoreEndpointCase, apiVersionDef.ExtendedPaths.MockResponse, MockResponse, conf)
	ignoredPaths := a.compileExtendedPathSpec(apiVersionDef.IgnoreEndpointCase, apiVersionDef.ExtendedPaths.Ignored, Ignored, conf)
	blackListPaths := a.compileExtendedPathSpec(apiVersionDef.IgnoreEndpointCase, apiVersionDef.ExtendedPaths.BlackList, BlackList, conf)
	whiteListPaths := a.compileExtendedPathSpec(apiVersionDef.IgnoreEndpointCase, apiVersionDef.ExtendedPaths.WhiteList, WhiteList, conf)
	cachedPaths := a.compileCachedPathSpec(apiVersionDef.ExtendedPaths.Cached, apiVersionDef.ExtendedPaths.AdvanceCacheConfig, conf)
	transformPaths := a.compileTransformPathSpec(apiVersionDef.ExtendedPaths.Transform, Transformed, conf)
	transformResponsePaths := a.compileTransformPathSpec(apiVersionDef.ExtendedPaths.TransformResponse, TransformedResponse, conf)
	transformJQPaths := a.compileTransformJQPathSpec(apiVersionDef.ExtendedPaths.TransformJQ, TransformedJQ)
	transformJQResponsePaths := a.compileTransformJQPathSpec(apiVersionDef.ExtendedPaths.TransformJQResponse, TransformedJQResponse)
	headerTransformPaths := a.compileInjectedHeaderSpec(apiVersionDef.ExtendedPaths.TransformHeader, HeaderInjected, conf)
	headerTransformPathsOnResponse := a.compileInjectedHeaderSpec(apiVersionDef.ExtendedPaths.TransformResponseHeader, HeaderInjectedResponse, conf)
	hardTimeouts := a.compileTimeoutPathSpec(apiVersionDef.ExtendedPaths.HardTimeouts, HardTimeout, conf)
	circuitBreakers := a.compileCircuitBreakerPathSpec(apiVersionDef.ExtendedPaths.CircuitBreaker, CircuitBreaker, apiSpec, conf)
	urlRewrites := a.compileURLRewritesPathSpec(apiVersionDef.ExtendedPaths.URLRewrite, URLRewrite, conf)
	virtualPaths := a.compileVirtualPathsSpec(apiVersionDef.ExtendedPaths.Virtual, VirtualPath, apiSpec, conf)
	requestSizes := a.compileRequestSizePathSpec(apiVersionDef.ExtendedPaths.SizeLimit, RequestSizeLimit, conf)
	methodTransforms := a.compileMethodTransformSpec(apiVersionDef.ExtendedPaths.MethodTransforms, MethodTransformed, conf)
	trackedPaths := a.compileTrackedEndpointPathsSpec(apiVersionDef.ExtendedPaths.TrackEndpoints, RequestTracked, conf)
	unTrackedPaths := a.compileUnTrackedEndpointPathsSpec(apiVersionDef.ExtendedPaths.DoNotTrackEndpoints, RequestNotTracked, conf)
	validateJSON := a.compileValidateJSONPathsSpec(apiVersionDef.ExtendedPaths.ValidateJSON, ValidateJSONRequest, conf)
	internalPaths := a.compileInternalPathsSpec(apiVersionDef.ExtendedPaths.Internal, Internal, conf)
	goPlugins := a.compileGopluginPathsSpec(apiVersionDef.ExtendedPaths.GoPlugin, GoPlugin, apiSpec, conf)
	persistGraphQL := a.compilePersistGraphQLPathSpec(apiVersionDef.ExtendedPaths.PersistGraphQL, PersistGraphQL, apiSpec, conf)
	rateLimitPaths := a.compileRateLimitPathsSpec(apiVersionDef.ExtendedPaths.RateLimit, RateLimit, conf)

	combinedPath := []URLSpec{}
	combinedPath = append(combinedPath, mockResponsePaths...)
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
	combinedPath = append(combinedPath, goPlugins...)
	combinedPath = append(combinedPath, persistGraphQL...)
	combinedPath = append(combinedPath, virtualPaths...)
	combinedPath = append(combinedPath, methodTransforms...)
	combinedPath = append(combinedPath, trackedPaths...)
	combinedPath = append(combinedPath, unTrackedPaths...)
	combinedPath = append(combinedPath, validateJSON...)
	combinedPath = append(combinedPath, internalPaths...)
	combinedPath = append(combinedPath, rateLimitPaths...)

	return combinedPath, len(whiteListPaths) > 0
}

func (a *APISpec) Init(authStore, sessionStore, healthStore, orgStore storage.Handler) {
	a.AuthManager.Init(authStore)
	a.Health.Init(healthStore)
	a.OrgSessionManager.Init(orgStore)
}

func (a *APISpec) StopSessionManagerPool() {
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
	case GoPlugin:
		return StatusGoPlugin
	case PersistGraphQL:
		return StatusPersistGraphQL
	case RateLimit:
		return StatusRateLimit
	default:
		log.Error("URL Status was not one of Ignored, Blacklist or WhiteList! Blocking.")
		return EndPointNotAllowed
	}
}

// URLAllowedAndIgnored checks if a url is allowed and ignored.
func (a *APISpec) URLAllowedAndIgnored(r *http.Request, rxPaths []URLSpec, whiteListStatus bool) (RequestStatus, interface{}) {
	for i := range rxPaths {
		if !rxPaths[i].matchesPath(r.URL.Path, a) {
			continue
		}

		if r.Method == rxPaths[i].Internal.Method && rxPaths[i].Status == Internal && !ctxLoopingEnabled(r) {
			return EndPointNotAllowed, nil
		}
	}

	// Check if ignored
	for i := range rxPaths {
		if !rxPaths[i].matchesPath(r.URL.Path, a) {
			continue
		}

		if rxPaths[i].MethodActions == nil {
			switch rxPaths[i].Status {
			case WhiteList:
				if rxPaths[i].Whitelist.Method != "" {
					if rxPaths[i].Whitelist.Method != r.Method {
						continue
					}

					return a.getURLStatus(rxPaths[i].Status), nil
				}
			case BlackList:
				if rxPaths[i].Blacklist.Method != "" {
					if rxPaths[i].Blacklist.Method != r.Method {
						continue
					}

					return a.getURLStatus(rxPaths[i].Status), nil
				}
			case Ignored:
				if rxPaths[i].Ignored.Method != "" {
					if rxPaths[i].Ignored.Method != r.Method {
						continue
					}
				}

				return a.getURLStatus(rxPaths[i].Status), nil
			case MockResponse:
				if rxPaths[i].MockResponse.Method != r.Method {
					continue
				}

				return StatusRedirectFlowByReply, rxPaths[i].MockResponse
			}
		} else { // Deprecated
			// We are using an extended path set, check for the method
			methodMeta, matchMethodOk := rxPaths[i].MethodActions[r.Method]
			if !matchMethodOk {
				continue
			}

			// Matched the method, check what status it is
			// TODO: Extend here for additional reply options
			switch methodMeta.Action {
			case apidef.NoAction:
				// NoAction status means we're not treating this request in any special or exceptional way
				return a.getURLStatus(rxPaths[i].Status), nil
			case apidef.Reply:
				return StatusRedirectFlowByReply, &methodMeta
			default:
				log.Error("URL Method Action was not set to NoAction, blocking.")
				return EndPointNotAllowed, nil
			}
		}

		if whiteListStatus {
			// We have a whitelist, nothing gets through unless specifically defined
			switch rxPaths[i].Status {
			case WhiteList, BlackList, Ignored:
			default:
				if rxPaths[i].Status == Internal && r.Method == rxPaths[i].Internal.Method && ctxLoopingEnabled(r) {
					return a.getURLStatus(rxPaths[i].Status), nil
				} else {
					return EndPointNotAllowed, nil
				}
			}
		}

		if rxPaths[i].TransformAction.Template != nil {
			return a.getURLStatus(rxPaths[i].Status), &rxPaths[i].TransformAction
		}

		if rxPaths[i].TransformJQAction.Filter != "" {
			return a.getURLStatus(rxPaths[i].Status), &rxPaths[i].TransformJQAction
		}

		// TODO: Fix, Not a great detection method
		if len(rxPaths[i].InjectHeaders.Path) > 0 {
			return a.getURLStatus(rxPaths[i].Status), &rxPaths[i].InjectHeaders
		}

		// Using a legacy path, handle it raw.
		return a.getURLStatus(rxPaths[i].Status), nil
	}

	// Nothing matched - should we still let it through?
	if whiteListStatus {
		// We have a whitelist, nothing gets through unless specifically defined
		return EndPointNotAllowed, nil
	}

	// No whitelist, but also not in any of the other lists, let it through and filter
	return StatusOk, nil
}

func (a *APISpec) getVersionFromRequest(r *http.Request) string {
	if vName := ctxGetVersionName(r); vName != nil {
		return *vName
	}

	if a.VersionData.NotVersioned && !a.VersionDefinition.Enabled {
		return ""
	}

	var vName string
	defer ctxSetVersionName(r, &vName)

	switch a.VersionDefinition.Location {
	case apidef.HeaderLocation:
		vName = r.Header.Get(a.VersionDefinition.Key)
		if a.VersionDefinition.StripVersioningData {
			log.Debug("Stripping version from header: ", vName)
			defer r.Header.Del(a.VersionDefinition.Key)
		}

		return vName
	case apidef.URLParamLocation:
		vName = r.URL.Query().Get(a.VersionDefinition.Key)
		if a.VersionDefinition.StripVersioningData {
			log.Debug("Stripping version from query: ", vName)
			q := r.URL.Query()
			q.Del(a.VersionDefinition.Key)
			r.URL.RawQuery = q.Encode()
		}

		return vName
	case apidef.URLLocation:
		uPath := a.StripListenPath(r.URL.Path)
		uPath = strings.TrimPrefix(uPath, "/"+a.Slug)

		// First non-empty part of the path is the version ID
		for _, part := range strings.Split(uPath, "/") {
			if part != "" {
				matchesUrlVersioningPattern := true
				if a.VersionDefinition.UrlVersioningPattern != "" {
					re, err := regexp.Compile(a.VersionDefinition.UrlVersioningPattern)
					if err != nil {
						log.Error("Error compiling versioning pattern: ", err)
					} else {
						matchesUrlVersioningPattern = re.Match([]byte(part))
					}
				}

				if (a.VersionDefinition.StripVersioningData || a.VersionDefinition.StripPath) && matchesUrlVersioningPattern {
					log.Debug("Stripping version from url: ", part)

					r.URL.Path = strings.Replace(r.URL.Path, part+"/", "", 1)
					r.URL.RawPath = strings.Replace(r.URL.RawPath, part+"/", "", 1)
				}

				//never delete this line as there's an easy to miss defer statement above
				vName = part

				return part
			}
		}
	}

	return ""
}

// RequestValid will check if an incoming request has valid version
// data and return a RequestStatus that describes the status of the
// request
func (a *APISpec) RequestValid(r *http.Request) (bool, RequestStatus) {
	versionInfo, status := a.Version(r)

	// Screwed up version info - fail and pass through
	if status != StatusOk {
		return false, status
	}

	// Load path data and whitelist data for version
	versionPaths, ok := a.RxPaths[versionInfo.Name]
	if !ok {
		log.Error("no RX Paths found for version ", versionInfo.Name)
		return false, VersionDoesNotExist
	}

	whiteListStatus, ok := a.WhiteListEnabled[versionInfo.Name]
	if !ok {
		log.Error("no whitelist data found")
		return false, VersionWhiteListStatusNotFound
	}

	if a.VersionData.NotVersioned && a.Expired() {
		return false, APIExpired
	} else if !a.VersionData.NotVersioned && versionInfo.Expired() { // Deprecated
		return false, VersionExpired
	}

	// not expired, let's check path info
	status, _ = a.URLAllowedAndIgnored(r, versionPaths, whiteListStatus)
	switch status {
	case EndPointNotAllowed:
		return false, status
	case StatusRedirectFlowByReply:
		return true, status
	case StatusOkAndIgnore, StatusCached, StatusTransform,
		StatusHeaderInjected, StatusMethodTransformed:
		return true, status
	default:
		return true, StatusOk
	}
}

func (a *APISpec) Expired() bool {
	// Never expires
	if a.Expiration == "" || a.Expiration == "-1" {
		return false
	}

	// otherwise use parsed timestamp
	if a.ExpirationTs.IsZero() {
		log.Error("Could not parse expiration date, disallow")
		return true
	}

	return time.Since(a.ExpirationTs) >= 0
}

// Version attempts to extract the version data from a request, depending on where it is stored in the
// request (currently only "header" is supported)
func (a *APISpec) Version(r *http.Request) (*apidef.VersionInfo, RequestStatus) {
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
					return &version, VersionNotFound
				}
				vName = a.VersionData.DefaultVersion
				ctxSetDefaultVersion(r)
			}
			// Load Version Data - General
			var ok bool
			if version, ok = a.VersionData.Versions[vName]; !ok {
				if a.VersionDefinition.FallbackToDefault {
					log.Debugf("fallback to default version: %s", a.VersionData.DefaultVersion)
					if version, ok = a.VersionData.Versions[a.VersionData.DefaultVersion]; ok {
						return &version, StatusOk
					}
				}

				return &version, VersionDoesNotExist
			}
		}

		// cache for the future
		ctxSetVersionInfo(r, &version)
	}

	return &version, StatusOk
}

// StripListenPath will strip the listen path from the URL, keeping version in tact.
func (a *APISpec) StripListenPath(reqPath string) string {
	return httputil.StripListenPath(a.Proxy.ListenPath, reqPath)
}

// StripVersionPath will strip the version from the URL. The input URL
// should already have listen path stripped.
func (a *APISpec) StripVersionPath(reqPath string) string {
	// First part of the url is the version fragment
	part := strings.Split(strings.Trim(reqPath, "/"), "/")[0]

	matchesUrlVersioningPattern := true
	if a.VersionDefinition.UrlVersioningPattern != "" {
		re, err := regexp.Compile(a.VersionDefinition.UrlVersioningPattern)
		if err != nil {
			log.Error("Error compiling versioning pattern: ", err)
		} else {
			matchesUrlVersioningPattern = re.Match([]byte(part))
		}
	}

	if (a.VersionDefinition.StripVersioningData || a.VersionDefinition.StripPath) && matchesUrlVersioningPattern {
		return strings.Replace(reqPath, "/"+part+"/", "/", 1)
	}

	return reqPath
}

func (a *APISpec) SanitizeProxyPaths(r *http.Request) {
	if !a.Proxy.StripListenPath {
		return
	}

	log.Debug("Stripping proxy listen path: ", a.Proxy.ListenPath)

	r.URL.Path = a.StripListenPath(r.URL.Path)
	if r.URL.RawPath != "" {
		r.URL.RawPath = a.StripListenPath(r.URL.RawPath)
	}

	log.Debug("Upstream path is: ", r.URL.Path)
}

func (a *APISpec) setHasMock() {
	if !a.IsOAS {
		a.HasMock = false
		return
	}

	middleware := a.OAS.GetTykMiddleware()
	if middleware == nil {
		a.HasMock = false
		return
	}

	if len(middleware.Operations) == 0 {
		a.HasMock = false
		return
	}

	for _, operation := range middleware.Operations {
		if operation.MockResponse == nil {
			continue
		}

		if operation.MockResponse.Enabled {
			a.HasMock = true
			return
		}
	}

	a.HasMock = false
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

func (s *APISpec) hasVirtualEndpoint() bool {
	for _, version := range s.VersionData.Versions {
		for _, virtual := range version.ExtendedPaths.Virtual {
			if !virtual.Disabled {
				return true
			}
		}
	}

	return false
}

// isListeningOnPort checks whether the API listens on the given port.
func (s *APISpec) isListeningOnPort(port int, gwConfig *config.Config) bool {
	if s.ListenPort == 0 {
		return gwConfig.ListenPort == port
	}

	return s.ListenPort == port
}

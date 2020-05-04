package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
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
	"strconv"
	"strings"

	"sync"
	"time"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/garyburd/redigo/redis"
	"github.com/gorilla/mux"
	"github.com/hashicorp/go-retryablehttp"
	"gopkg.in/yaml.v2"
)

//nolint
var (
	TykJWTAPIKeyEndpoint        = "/tyk/keys/"
	TykMiddlewareBundleNameHash = "c343271e0935000c0ea41f8d9822015c"
	TykBundles                  = "bundles"
	TykMiddlewareBundleName     = "bundle.zip"
	TykMiddlewareFile           = "middleware.py"
	TykManifest                 = "manifest.json"

	TykRoot  = "/data/tyk-gateway/"
	CertRoot = "/certs/"
	CfgRoot  = "/data/config/"

	//Local Dev Vars
	// TykRoot  = "/local/nuchat/tyk-workspace"
	// CertRoot = "/local/nuchat/tyk-workspace/certs/"
	// CfgRoot  = "/local/nuchat/tyk-workspace/data/config"

	TykCACert                    = CertRoot + "cacerts.crt"
	TykServerCrt                 = CertRoot + "server.crt"
	TykServerKey                 = CertRoot + "server.key"
	TykUpstreamPem               = CertRoot + "upstream.pem"
	SystemConfigFilePath         = CfgRoot + "systemconfig.yaml"
	TykMiddlewareRoot            = TykRoot + "/middleware/"
	TykMiddlewareSrcFile         = TykRoot + TykMiddlewareFile
	TykMiddlewareManifestSrcFile = TykRoot + TykManifest
	JWTDefinitionsSpec           = TykRoot + "/jwt_definition.json"
	TykConfFilePath              = TykRoot + "/tyk.conf"
	JWTApiKeySpec                = TykRoot + "/token_jwt.json"
	APITemplateOpenSpec          = TykRoot + "/api_template_open.json"
	APITemplateJWTSpec           = TykRoot + "/api_template_jwt.json"
	APIDefinitionRedis           = TykRoot + "/api_definitions.json"
	DynamicAPIConnTimeout        = 20000
	JWTKeyPrefix                 = "JWT-KEY-"
)

type Event int

var m sync.Mutex

const (
	ADD    Event = 0
	DELETE Event = 1
)

// URLRewrite struct to store URLRewrite
type URLRewrites struct {
	Path         string   `json:"path"`
	Method       string   `json:"method"`
	MatchPattern string   `json:"match_pattern"`
	RewriteTo    string   `json:"rewrite_to"`
	Triggers     []string `json:"triggers"`
	MatchRegexp  string   `json:"match_regexp"`
}

// Middleware config data
type PythonMiddlewareConfigData struct {
	InjectK8sAuthHeader bool   `json:"inject_k8s_auth_header"`
	InjectJwtHeader     bool   `json:"inject_jwt_headers"`
	K8sAuthTokenPath    string `json:"k8s_auth_token_path"`
	InjectSecureToken   bool   `json:"inject_secure_token"`
	SecureTokenPath     string `json:"secure_token_path"`
}

// Golang Middleware config data
type GolangMiddlewareConfigData struct {
	Path string `json:"path"`
	Name string `json:"name"`
}

// APIDefinition to store api definition
type APIDefinition struct {
	Name                       string                     `json:"name"`
	ListenPath                 string                     `json:"listen_path"`
	TargetURL                  string                     `json:"target_url"`
	AuthType                   string                     `json:"authtype"`
	EnablePythonMiddleware     bool                       `json:"enable_python_middleware"`
	EnableGolangMiddleware     bool                       `json:"enable_golang_middleware"`
	EnableMTLS                 bool                       `json:"enable_mtls"`
	UpdateTargetHost           bool                       `json:"update_target_host"`
	PythonMiddlewareConfigData PythonMiddlewareConfigData `json:"python_middleware_config_data"`
	GolangMiddlewareConfigData GolangMiddlewareConfigData `json:"golang_middleware_config_data"`
	URLRewrites                []URLRewrites              `json:"url_rewrites"`
	RemoveHeaders              []string                   `json:"remove_headers"`
	AuthCookieName             string                     `json:"auth_cookie_name"`
	EnableLoadBalancing        bool                       `json:"enable_load_balancing"`
	LoadBalancingConfigData    LoadBalancingConfigData    `json:"load_balancing_config_data"`
	SSLForceRootCACheck        bool                       `json:"ssl_force_rootca_check"`
	AppName                    string                     `json:"app_name"`
}

// JWTDefinitions to store JWTDefinition
type JWTDefinition struct {
	AppName      string   `json:"app_name"`
	AppNameList  []string `json:"app_name_list"`
	JWTPublicKey string   `json:"jwt_public_key"`
	JWTAPIKey    string   `json:"jwt_api_key"`
}

type ServiceAPIS map[string][]APIDefinition

// // JWTDefinitions to store JWTDefinitions
// type JWTDefinitions struct {
// 	JWTDefinitions []JWTDefinition `json:"jwt_definitions"`
// }

// TokenAccessRights to store token api access rights
type TokenAccessRights struct {
	APIID       string   `json:"api_id"`
	APIName     string   `json:"api_name"`
	Versions    []string `json:"versions"`
	AllowedURLS []string `json:"allowed_urls"`
	Limit       *string  `json:"limit"`
}

type GolangManifest struct {
	Checksum         string           `json:"checksum"`
	Signature        string           `json:"signature"`
	CustomMiddleware CustomMiddleware `json:"custom_middleware"`
}

type Post struct {
	Name           string `json:"name"`
	Path           string `json:"path"`
	RequireSession bool   `json:"require_session"`
}

type CustomMiddleware struct {
	Post   []Post `json:"post"`
	Driver string `json:"driver"`
}

type HostCheckObject struct {
	CheckURL string            `json:"url"`
	Method   string            `json:"method"`
	Headers  map[string]string `json:"headers"`
	Body     string            `json:"body"`
}

type ServiceDiscoveryConfiguration struct {
	UseDiscoveryService bool   `json:"use_discovery_service"`
	QueryEndpoint       string `json:"query_endpoint"`
	UseNestedQuery      bool   `json:"use_nested_query"`
	ParentDataPath      string `json:"parent_data_path"`
	DataPath            string `json:"data_path"`
	PortDataPath        string `json:"port_data_path"`
	TargetPath          string `json:"target_path"`
	UseTargetList       bool   `json:"use_target_list"`
	CacheTimeout        int64  `json:"cache_timeout"`
	EndpointReturnsList bool   `json:"endpoint_returns_list"`
}

type LoadBalancingConfigData struct {
	CheckList []HostCheckObject `json:"check_list"`
	Config    struct {
		ExpireUptimeAnalyticsAfter int64                         `json:"expire_utime_after"`
		ServiceDiscovery           ServiceDiscoveryConfiguration `json:"service_discovery"`
		RecheckWait                int                           `json:"recheck_wait"`
	}
}

func keyLoader(w http.ResponseWriter, r *http.Request) {
	log.Info("Requesting mutex")
	m.Lock()
	defer m.Unlock()

	var obj interface{}
	var code int

	appName := mux.Vars(r)["appName"]
	keyID := mux.Vars(r)["kid"]

	switch r.Method {
	//All JWT Keys comes from db 2
	case "GET":
		if keyID != "" && appName != "" {
			log.Debug(fmt.Sprintf("Requesting JWT Key %s for app %s", appName, keyID))
			obj, code = handleGetKey(appName, keyID)
		} else if appName != "" && keyID == "" {
			log.Debug("Requesting JWT Keys list for app ", appName)
			obj, code = handleGetKey(appName, "")
		} else {
			log.Debug("Requesting JWT Keys list for all Apps")
			obj, code = handleGetKey("", "")
		}
	case "POST":
		if strings.Contains(r.URL.Path, "/key/refresh") && appName != "" {
			obj, code = refreshKeys(appName)
		} else {
			obj, code = updateKeys(r)
		}
	case "DELETE":
		if keyID != "" && appName != "" {
			log.Info(fmt.Sprintf("Deleting JWT Key %s for appName %s", keyID, appName))
			obj, code = deleteJWTKey(keyID, appName)
		} else {
			obj, code = apiError("Delete Usage: /tyk/key/<appName>/<kid>"), http.StatusBadRequest
		}
	}

	doJSONWrite(w, code, obj)

	log.Info("Releasing mutex")
}

func handleGetKey(appName string, kid string) (interface{}, int) {
	c := GetRedisConn()
	defer c.Close()

	var jwtKey map[string]interface{}

	if kid != "" {
		data, err := redis.String(c.Do("GET", JWTKeyPrefix+appName+"-"+kid))
		if err != nil {
			log.Error("Error reading JWT key from Redis", err)
			return apiError("key not found"), http.StatusInternalServerError
		}
		_ = json.Unmarshal([]byte(data), &jwtKey)
		return jwtKey, http.StatusOK
	} else if appName != "" && kid == "" {
		//Get all key matching JWTKeyPrefix-appName
		keys, err := redis.Strings(c.Do("KEYS", JWTKeyPrefix+appName+"-"+"*"))
		if err != nil {
			log.Error("Could not get JWT list for app from Redis", appName, err)
			return apiError("could not get jwt key list"), http.StatusInternalServerError
		}
		return keys, http.StatusOK
	} else if appName == "" && kid == "" {
		keys, err := redis.Strings(c.Do("KEYS", JWTKeyPrefix+"*"))
		if err != nil {
			log.Error("Could not get JWT list from Redis", err)
			return apiError("could not get jwt key list"), http.StatusInternalServerError
		}
		return keys, http.StatusOK
	}
	return jwtKey, http.StatusOK
}

func apiLoader(w http.ResponseWriter, r *http.Request) {
	log.Info("Requesting mutex")
	m.Lock()
	defer m.Unlock()

	service := mux.Vars(r)["service"]
	apiName := mux.Vars(r)["apiName"]

	apiID := service + "-" + apiName

	var obj interface{}
	var code int

	switch r.Method {
	// GET remains same - Read apis from memory
	case "GET":
		if apiName != "" && service != "" {
			log.Debug("Requesting API definition for", apiID)
			obj, code = handleGetAPI(apiID)
		} else {
			log.Debug("Requesting API list")
			obj, code = handleGetAPIList()
		}
	case "POST":
		if apiName == "" && service == "" {
			log.Debug("Creating new definition")
			obj, code = addOrUpdateApi(r)
		} else {
			obj, code = apiError("Can not Add/Update service specific APIs. Use /tyk/api or /tyk/key/refresh endpoint"), http.StatusBadRequest
		}
	case "DELETE":
		if apiName != "" && service != "" {
			log.Info("Deleting Individual API not supported")
			obj, code = apiError("Must specify an /service to delete API"), http.StatusBadRequest
		} else if service != "" && apiName == "" {
			log.Info("Deleting API definition for service: ", service)
			obj, code = deleteAPIByService(service)
		} else {
			obj, code = apiError("Must specify an /service to delete API"), http.StatusBadRequest
		}
	}

	doJSONWrite(w, code, obj)

	log.Info("Releasing mutex")
}

func deleteJWTKey(keyID string, appName string) (interface{}, int) {
	var tykConf map[string]interface{}

	tykConfData, err := ioutil.ReadFile(TykConfFilePath)
	if err != nil {
		log.Error("Error reading TyK conf", err)
		return apiError("could not get authorization token"), http.StatusInternalServerError
	}

	err = json.Unmarshal(tykConfData, &tykConf)
	if err != nil {
		log.Error("Error decoding TyK conf", err)
		return apiError("authorization token decode error"), http.StatusInternalServerError
	}
	c := GetRedisConn()
	defer c.Close()
	jwtKey := JWTKeyPrefix + appName + "-" + keyID

	if ok, _ := redis.Bool(c.Do("EXISTS", jwtKey)); ok {
		_, err = c.Do("DEL", jwtKey)
		if err != nil {
			log.Error(fmt.Sprintf("Error deleting Key %s from Redis %v", jwtKey, err))
			return apiError("Error deleting Key"), http.StatusInternalServerError
		}
	} else {
		return apiError("Key not found"), http.StatusInternalServerError
	}

	// Delete JWT API
	//JWTApiKey := strings.TrimPrefix(jwtKey, JWTKeyPrefix)
	// JWTApiKey = keyID
	endPoint := getTykEndpoint("localhost", TykJWTAPIKeyEndpoint) + keyID
	client, ret := GetHTTPClient()
	if ret == false {
		return apiError("http client error. could not delete jwt key"), http.StatusInternalServerError
	}

	req, err := retryablehttp.NewRequest("DELETE", endPoint, nil)
	if err != nil {
		log.Error("Error creating jwt api key DELETE request", err)
		return apiError("Error deleting JWT Key"), http.StatusInternalServerError
	}

	req.Header.Add("X-Tyk-Authorization", tykConf["secret"].(string))
	//Suppress quota reset
	q := req.URL.Query()
	q.Add("suppress_reset", "1")
	req.URL.RawQuery = q.Encode()

	log.Info("Deleting JWT Token:", string(keyID))
	resp, err := client.Do(req)
	if err != nil {
		log.Error("Error in jwt api key DELETE", err)
		return apiError("http client error. could not delete jwt key"), http.StatusInternalServerError
	}
	defer resp.Body.Close()

	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error("Error reading response body", err)
		return apiError("http client error. could not delete jwt key"), http.StatusInternalServerError
	}

	if resp.StatusCode == 200 {
		log.Info("Deleted JWT API Token")
	} else {
		log.Error("error deleting JWT key")
		return apiError("http client error. could not delete jwt key"), http.StatusInternalServerError
	}

	response := apiModifyKeySuccess{
		Status: "ok",
		Action: "deleted",
	}

	return response, http.StatusOK
}

//On Posting JWT Key
func updateKeys(r *http.Request) (interface{}, int) {
	//Add key to Redis and call addOrUpdateJWTKey
	var jwtDef JWTDefinition
	//Receive JWT payload
	data, err := receivePayload(r)
	if err != nil {
		return apiError(err.Error()), http.StatusBadRequest
	}

	err = json.Unmarshal(data, &jwtDef)
	if err != nil {
		log.Error("Couldn't decode new JWT Definition object: ", err)
		return apiError("Malformed request"), http.StatusBadRequest
	}

	c := GetRedisConn()
	defer c.Close()

	//Store JWT to Redis DB
	key := JWTKeyPrefix + jwtDef.AppName + "-" + jwtDef.JWTAPIKey

	jwtJSON, _ := json.Marshal(jwtDef)

	_, err = c.Do("SET", key, jwtJSON)
	if err != nil {
		return apiError("Could not add jwt key to redis store"), http.StatusInternalServerError
	}

	err = addOrUpdateJWTKey(jwtDef)
	if err != nil {
		return apiError("Could not update api key"), http.StatusInternalServerError
	}

	response := apiModifyKeySuccess{
		Status: "ok",
		Action: "updated",
	}

	return response, http.StatusOK
}

func refreshKeys(appName string) (interface{}, int) {
	c := GetRedisConn()
	defer c.Close()

	//Get All JWT keys belonging to appName and call addOrUpdateJWTKey
	keys, err := redis.Strings(c.Do("KEYS", JWTKeyPrefix+appName+"-"+"*"))
	if err != nil {
		log.Error("Could not get Key list from Redis", err)
		return apiError("Could not get Key list"), http.StatusInternalServerError
	}

	log.Debug(fmt.Sprintf("Refresh Key List %v ", keys))

	for _, key := range keys {
		jwtDef := JWTDefinition{}
		jwtKeyData, err := redis.String(c.Do("GET", key))
		if err != nil {
			log.Error("Error reading API from Redis", err)
			return apiError("Error reading API from Redis"), http.StatusInternalServerError
		}

		if err := json.NewDecoder(strings.NewReader(jwtKeyData)).Decode(&jwtDef); err != nil {
			return apiError("Could not decode api definition"), http.StatusInternalServerError
		}

		err = addOrUpdateJWTKey(jwtDef)
		if err != nil {
			log.Error("Could not update JWT Key", err)
			return apiError("Could not update api key"), http.StatusInternalServerError
		}
	}

	response := apiModifyKeySuccess{
		Status: "ok",
		Action: "updated",
	}

	return response, http.StatusOK
}

func receivePayload(r *http.Request) ([]byte, error) {
	connTimeout := DynamicAPIConnTimeout
	log.Info("Updating/Adding API to redis")
	c := GetRedisConn()
	defer c.Close()

	if config.Global().UseDBAppConfigs {
		log.Error("Rejected new API Definition due to UseDBAppConfigs = true")
		return nil, errors.New("Due to enabled use_db_app_configs, please use the Dashboard API")
	}

	if config.Global().DynamicAPIConnTimeout == 0 {
		connTimeout = DynamicAPIConnTimeout
	} else {
		connTimeout = config.Global().DynamicAPIConnTimeout
	}

	buf := make([]byte, 1*1024*1024)
	var data []byte
	count := 0
	start := time.Now()
	log.Debug("Process Request")
	for {
		n, err := r.Body.Read(buf)
		data = Append(data, buf[0:n])
		count += n

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Error("Error reading payload", err)
			return nil, errors.New("Request malformed")
		}

		t := time.Now()
		elapsed := t.Sub(start)

		if elapsed.Nanoseconds()/1000000 > int64(connTimeout) {
			log.Error("request timed out")
			return nil, errors.New("request timeout")
		}
		time.Sleep(2 * time.Millisecond)
	}
	log.Debug("Received data length : ", count)
	return data, nil
}

func addOrUpdateApi(r *http.Request) (interface{}, int) {
	log.Info("Updating/Adding API to redis")
	c := GetRedisConn()
	defer c.Close()

	var ServApis ServiceAPIS
	var existingApis ServiceAPIS
	var appName string

	//Non-blocking read
	data, err := receivePayload(r)
	if err != nil {
		return apiError(err.Error()), http.StatusBadRequest
	}

	err = json.Unmarshal(data, &ServApis)
	if err != nil {
		log.Error("Couldn't decode new API Definition object: ", err)
		return apiError("Request malformed"), http.StatusBadRequest
	}

	//Check if mtls files are present
	_, err = os.Stat(TykServerCrt)
	if os.IsNotExist(err) {
		return apiError("apigw server cert not found. Try after some time"), http.StatusInternalServerError
	}

	_, err = os.Stat(TykServerKey)
	if os.IsNotExist(err) {
		return apiError("apigw server key not found. Try after some time"), http.StatusInternalServerError
	}

	_, err = os.Stat(TykUpstreamPem)
	if os.IsNotExist(err) {
		return apiError("mtls upstream pem not found. Try after some time"), http.StatusInternalServerError
	}

	OpenAPI, err := ioutil.ReadFile(APITemplateOpenSpec)
	if err != nil {
		return apiError("Internal Error. Try after some time"), http.StatusInternalServerError
	}

	JWTAPI, err := ioutil.ReadFile(APITemplateJWTSpec)
	if err != nil {
		return apiError("Internal Error. Try after some time"), http.StatusInternalServerError
	}

	host, err := getInbandIP(SystemConfigFilePath)
	if err != nil {
		return apiError("Could not get inband IP"), http.StatusInternalServerError
	}

	// Load api_defintions.json file and check if incoming /v1/sites/<site-name> is loaded
	// if its present in api_definitions.json then override it with incoming definition
	// if not then add it to api_definitions.json
	// when KMS loads api_defitions.json it would be no-op if /v1/sites/<site-name> is present

	apiDefinitions, err := ioutil.ReadFile(APIDefinitionRedis)
	if err != nil {
		return apiError("Could not read api_definitions.json file"), http.StatusInternalServerError
	}

	err = json.Unmarshal(apiDefinitions, &existingApis)
	if err != nil {
		log.Error("Couldn't decode existing API Definition object: ", err)
		return apiError("Malformed api_definitions.json"), http.StatusBadRequest
	}

	for service, apis := range ServApis {
		log.Debug("Processing service: ", service)
		for _, api := range apis {
			var temp map[string]interface{}
			APIID := service + "-" + api.Name
			switch api.AuthType {
			case "open":
				json.Unmarshal(OpenAPI, &temp)
			case "jwt":
				json.Unmarshal(JWTAPI, &temp)
			default:
				return apiError("Unsupported auth type. It should be either open or jwt"), http.StatusBadRequest
			}

			temp["name"] = api.Name
			temp["api_id"] = APIID
			temp["slug"] = APIID
			temp["app_name"] = api.AppName

			//set appName
			appName = api.AppName

			//update target host
			if api.UpdateTargetHost {
				api.TargetURL = strings.Replace(api.TargetURL, "localhost", host, 1)
			}
			temp["proxy"].(map[string]interface{})["target_url"] = api.TargetURL

			temp["proxy"].(map[string]interface{})["listen_path"] = api.ListenPath
			if len(api.URLRewrites) > 0 {
				temp["version_data"].(map[string]interface {
				})["versions"].(map[string]interface {
				})["Default"].(map[string]interface {
				})["extended_paths"].(map[string]interface {
				})["url_rewrites"] = api.URLRewrites
			}

			if len(api.RemoveHeaders) > 0 {
				temp["version_data"].(map[string]interface {
				})["versions"].(map[string]interface {
				})["Default"].(map[string]interface {
				})["global_headers_remove"] = api.RemoveHeaders
			}

			if len(api.AuthCookieName) != 0 {
				temp["auth"].(map[string]interface {
				})["cookie_name"] = api.AuthCookieName

				temp["auth"].(map[string]interface {
				})["auth_header_name"] = api.AuthCookieName
			}

			// Inject middleware
			if api.EnablePythonMiddleware {
				log.Info("Adding custom middleware folder for python ", APIID)
				temp["custom_middleware_bundle"] = TykMiddlewareBundleName
				temp["config_data"] = api.PythonMiddlewareConfigData

				// Create api_hash folder under middleware
				middlewareBundlePath := strings.Join([]string{
					TykMiddlewareRoot, "/", TykBundles, "/", APIID, "_", TykMiddlewareBundleNameHash}, "")

				if _, err := os.Stat(middlewareBundlePath); os.IsNotExist(err) {
					// make folder and copy manifest and middleware.py to it
					err := os.MkdirAll(middlewareBundlePath, os.ModePerm)
					if err != nil {
						return apiError("Middleware Error"), http.StatusInternalServerError
					}

					middlewareDestination := strings.Join([]string{middlewareBundlePath, "/", TykMiddlewareFile}, "")
					middlewareSource := strings.Join([]string{TykMiddlewareSrcFile}, "")
					_, mErr := copyFile(middlewareSource, middlewareDestination)
					if mErr != nil {
						return apiError("Middleware Error"), http.StatusInternalServerError
					}

					manifestDestination := strings.Join([]string{middlewareBundlePath, "/", TykManifest}, "")
					manifestSource := strings.Join([]string{TykMiddlewareManifestSrcFile}, "")
					_, maErr := copyFile(manifestSource, manifestDestination)
					if maErr != nil {
						return apiError("Middleware Error"), http.StatusInternalServerError
					}

					log.Info("Added custom middleware folder for ", APIID)
				}
			}

			if api.EnableGolangMiddleware {
				log.Info("Adding custom middleware folder for golang ", APIID)
				temp["custom_middleware_bundle"] = TykMiddlewareBundleName
				//golang plugin does not have support for config_data

				// Create api_hash folder under middleware
				middlewareBundlePath := strings.Join([]string{
					TykMiddlewareRoot, "/", TykBundles, "/", APIID, "_", TykMiddlewareBundleNameHash}, "")

				middlewareBundlePathInK8S := strings.Join([]string{
					TykMiddlewareRoot, "/", TykBundles, "/", APIID, "_", TykMiddlewareBundleNameHash}, "")

				if _, err := os.Stat(middlewareBundlePath); os.IsNotExist(err) {
					// make folder and copy manifest and middleware.py to it
					err := os.MkdirAll(middlewareBundlePath, os.ModePerm)
					if err != nil {
						return apiError("Middleware Error"), http.StatusInternalServerError
					}

					//Copy shared object ".so" pointed by path to respective bundle folder
					middlewareDestination := strings.Join([]string{middlewareBundlePath, "/", api.GolangMiddlewareConfigData.Path}, "")
					middlewareSource := strings.Join([]string{TykRoot, "/", api.GolangMiddlewareConfigData.Path}, "")
					_, mErr := copyFile(middlewareSource, middlewareDestination)
					if mErr != nil {
						return apiError("Middleware Error"), http.StatusInternalServerError
					}

					//Read sample manifest file and marshel through the structure
					sharedObjectAbsPathInK8S := strings.Join(
						[]string{middlewareBundlePathInK8S, "/", api.GolangMiddlewareConfigData.Path}, "")

					gm := GolangManifest{Checksum: "", Signature: ""}
					post := Post{Name: api.GolangMiddlewareConfigData.Name, Path: sharedObjectAbsPathInK8S, RequireSession: false}
					gm.CustomMiddleware.Post = append(gm.CustomMiddleware.Post, post)
					gm.CustomMiddleware.Driver = "goplugin"

					data, gErr := json.MarshalIndent(gm, "", "  ")
					if gErr != nil {
						return apiError("Middleware Error"), http.StatusInternalServerError
					}

					manifestDestination := strings.Join([]string{middlewareBundlePath, "/", TykManifest}, "")

					err = ioutil.WriteFile(manifestDestination, data, 0644)
					if err != nil {
						return apiError("Middleware Error"), http.StatusInternalServerError
					}

					log.Info("Added golang middleware folder for ", APIID)
				}
			}

			if api.EnableMTLS {
				var certs = map[string]string{}

				certs["*"] = TykUpstreamPem
				temp["upstream_certificates"] = certs
			}

			if api.EnableLoadBalancing {
				temp["uptime_tests"] = api.LoadBalancingConfigData
				temp["proxy"].(map[string]interface{})["check_host_against_uptime_tests"] = true
				temp["proxy"].(map[string]interface{})["enable_load_balancing"] = true
				temp["proxy"].(map[string]interface{})["service_discovery"] = api.LoadBalancingConfigData.Config.ServiceDiscovery
			}

			//Set ssl_force_rootca_check that was received from apigwmgr
			temp["proxy"].(map[string]interface {
			})["transport"].(map[string]interface {
			})["ssl_force_rootca_check"] = api.SSLForceRootCACheck

			//temp has the definition - add it to Redis
			apiJSON, _ := json.Marshal(temp)

			//Append service name while adding it to Redis for easy lookup while deleting APIs
			_, err = c.Do("SET", APIID, apiJSON)
			if err != nil {
				return apiError("Could not add api to redis store"), http.StatusInternalServerError
			}
		}

		//Add API to existingApis structure
		existingApis[service] = apis
	}

	// Reload All APIS and process the JWT APIs
	reloadURLStructure(nil)

	//read all existing JWT enabled apis, add new api_id and update the JWT token

	err = addOrDeleteJWTKey(ADD, appName)
	if err != nil {
		return apiError("Could not add JWT key"), http.StatusInternalServerError
	}
	// no need to relaod tyk after JET key adition - since JWT keys are stored in Redis and is dynamic lookup

	action := "modified"
	if r.Method == "POST" {
		action = "added"
	}

	response := apiModifyKeySuccess{
		Status: "ok",
		Action: action,
	}

	return response, http.StatusOK
}

//to Add and Update a JWT Key
func addOrUpdateJWTKey(jwtDef JWTDefinition) error {
	var JWTAPIMap = make(map[string]string)
	var tykConf map[string]interface{}

	tykConfData, err := ioutil.ReadFile(TykConfFilePath)
	if err != nil {
		log.Error("Error reading TyK conf", err)
		return err
	}

	err = json.Unmarshal(tykConfData, &tykConf)
	if err != nil {
		log.Error("Error decoding TyK conf", err)
		return err
	}

	c := GetRedisConn()
	defer c.Close()

	apis, err := redis.Strings(c.Do("KEYS", "*"))
	if err != nil {
		log.Error("Could not get API list from Redis", err)
		return err
	}

	for _, api := range apis {
		//Skip all keys with JWT-KEY- prefix
		if !strings.HasPrefix(api, JWTKeyPrefix) {
			log.Debug("Processing api %s", api)
			data, err := redis.String(c.Do("GET", api))
			if err != nil {
				log.Error("Error reading API from Redis", err)
				return err
			}

			var jsonApi map[string]interface{}
			err = json.Unmarshal([]byte(data), &jsonApi)

			//create JWT MAP of API belonging to appName
			//check if appNamelist contains jsonApi["app_name"]
			appName := fmt.Sprintf("%v", jsonApi["app_name"])
			if Contains(jwtDef.AppNameList, appName) && jsonApi["enable_jwt"] == true {
				apiID := jsonApi["api_id"].(string)
				name := jsonApi["name"].(string)
				JWTAPIMap[apiID] = name
			}
		}
	}
	log.Debug(fmt.Sprintf("App Name - %s  ---- JWT API Map %v ", appName, JWTAPIMap))

	//Base64 decode JWT key
	jwtPublicKey, err := base64.StdEncoding.DecodeString(jwtDef.JWTPublicKey)
	if err != nil {
		return err
	}

	log.Debug(fmt.Sprintf("JWT Public Key %s", jwtPublicKey))
	count := 0
	for {
		time.Sleep(3 * time.Second)
		ret := processJWTApiKey(tykConf, JWTAPIMap, jwtPublicKey, jwtDef.JWTAPIKey, "localhost", ADD)
		count++
		if ret == true {
			break
		} else if count < 3 {
			log.Warn("Could not verify JWT API Token.. retry")
		} else {
			log.Error("Could not add JWT token", jwtDef.JWTAPIKey)
			break
		}
	}

	return nil
}

//TODO - appName becomes the list
func addOrDeleteJWTKey(e Event, appName string) error {
	var JWTAPIMap = make(map[string]string)
	var tykConf map[string]interface{}

	tykConfData, err := ioutil.ReadFile(TykConfFilePath)
	if err != nil {
		log.Error("Error reading TyK conf", err)
		return err
	}

	err = json.Unmarshal(tykConfData, &tykConf)
	if err != nil {
		log.Error("Error decoding TyK conf", err)
		return err
	}

	c := GetRedisConn()
	defer c.Close()

	//Get All JWT KEYS
	//Check if appName is in app_name_list
	//   if present recreate the JWT MAP and upload the key with new map
	//   repeat this for all matching keys

	keys, err := redis.Strings(c.Do("KEYS", JWTKeyPrefix+"*"))
	if err != nil {
		log.Error("Could not get jwt key list from Redis", err)
		return err
	}

	// Go Over all JWT Keys
	for _, key := range keys {
		jwtDef := JWTDefinition{}
		jwtKeyData, err := redis.String(c.Do("GET", key))
		if err != nil {
			log.Error("Error reading Key from Redis", err)
			return err
		}
		if err := json.NewDecoder(strings.NewReader(jwtKeyData)).Decode(&jwtDef); err != nil {
			return err
		}

		//Check if appName is in app_name_list
		if Contains(jwtDef.AppNameList, appName) {
			//Create API MAP and update the key
			apis, err := redis.Strings(c.Do("KEYS", "*"))
			if err != nil {
				log.Error("Could not get API list from Redis", err)
				return err
			}

			for _, api := range apis {
				//Skip all keys with JWT-KEY- prefix
				if !strings.HasPrefix(api, JWTKeyPrefix) {
					log.Debug("Processing api %s", api)
					data, err := redis.String(c.Do("GET", api))
					if err != nil {
						log.Error("Error reading API from Redis", err)
						return err
					}

					var jsonApi map[string]interface{}
					err = json.Unmarshal([]byte(data), &jsonApi)

					//create JWT MAP of API belonging to appName
					aName := fmt.Sprintf("%v", jsonApi["app_name"])
					if Contains(jwtDef.AppNameList, aName) && jsonApi["enable_jwt"] == true {
						apiID := jsonApi["api_id"].(string)
						name := jsonApi["name"].(string)
						JWTAPIMap[apiID] = name
					}
				}
			}
		}
		//Update Key
		log.Debug(fmt.Sprintf("App Name - %s  ---- JWT API Map %v ", appName, JWTAPIMap))
		log.Debug(fmt.Sprintf("updating JWT key %s", jwtDef.JWTAPIKey))
		//Base64 decode JWT key
		jwtKey, err := base64.StdEncoding.DecodeString(jwtDef.JWTPublicKey)
		if err != nil {
			return err
		}
		count := 0
		for {
			time.Sleep(3 * time.Second)
			ret := processJWTApiKey(tykConf, JWTAPIMap, jwtKey, jwtDef.JWTAPIKey, "localhost", e)
			count++
			if ret == true {
				break
			} else if count < 3 {
				log.Warn("Could not verify JWT API Token.. retry")
			} else {
				log.Error("Could not add JWT token", jwtDef.JWTAPIKey)
				break
			}
		}
	}
	return nil
}

func processJWTApiKey(tykConf map[string]interface{},
	JWTAPIMap map[string]string, JWTPublicKey []byte, JWTApiKey string,
	host string, e Event) bool {

	var APIList = make(map[string]TokenAccessRights)
	var template map[string]interface{}

	for key, value := range JWTAPIMap {
		c := TokenAccessRights{APIID: key, APIName: value, Versions: []string{"Default"}, AllowedURLS: []string{}, Limit: nil}
		APIList[key] = c
	}

	//Read token_jwt.json template
	JWTTokenTemplate, err := ioutil.ReadFile(JWTApiKeySpec)
	if err != nil {
		log.Error("Error reading jwt api key template")
		return false
	}
	err = json.Unmarshal(JWTTokenTemplate, &template)
	if err != nil {
		log.Error("Error decoding jwt api key templated")
		return false
	}
	template["access_rights"] = APIList
	template["jwt_data"].(map[string]interface{})["secret"] = string(JWTPublicKey)
	outputJSON, _ := json.Marshal(template)
	JWTKey := strings.TrimSuffix(string(JWTApiKey), "\n")

	//Create Token
	client, ret := GetHTTPClient()
	if ret == false {
		return ret
	}

	var endPoint = getTykEndpoint(host, TykJWTAPIKeyEndpoint) + JWTKey

	// Update JWT key if adding new JWT API or deleting an JWT api from exsiting list
	if (e == ADD && len(JWTAPIMap) > 0) || (e == DELETE && len(JWTAPIMap) > 0) {
		req, err := retryablehttp.NewRequest("POST", endPoint, bytes.NewReader(outputJSON))
		if err != nil {
			log.Error("Error creating jwt api key POST request", err)
			return false
		}

		req.Header.Add("X-Tyk-Authorization", tykConf["secret"].(string))
		log.Info("Creating JWT Token: ", string(JWTApiKey))

		//Suppress quota reset
		q := req.URL.Query()
		q.Add("suppress_reset", "1")
		req.URL.RawQuery = q.Encode()

		resp, err := client.Do(req)
		if err != nil {
			log.Error("Error in jwt api key POST", err)
			return false
		}
		defer resp.Body.Close()

		_, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Error("Error reading response body", err)
			return false
		}

		if resp.StatusCode == 200 {
			log.Info("Created JWT API Token")
			//Check if the key was really created
			ret := checkIfJwtKeyCreated(tykConf, JWTKey, host)
			if !ret {
				return ret
			}
		} else {
			log.Error("Error Creating JWT API Token")
			return false
		}
	} else if e == DELETE && len(JWTAPIMap) == 0 {
		//Keep the key with no api map
		c := GetRedisConn()
		defer c.Close()

		jwtKey := JWTKeyPrefix + appName + "-" + JWTApiKey
		_, err = c.Do("DEL", jwtKey)
		if err != nil {
			log.Error("Error deleting JWT key ", jwtKey)
			return false
		}

		// Delete JWT API
		req, err := retryablehttp.NewRequest("DELETE", endPoint, bytes.NewReader(outputJSON))
		if err != nil {
			log.Error("Error creating jwt api key DELETE request", err)
			return false
		}

		req.Header.Add("X-Tyk-Authorization", tykConf["secret"].(string))
		//Suppress quota reset
		q := req.URL.Query()
		q.Add("suppress_reset", "1")
		req.URL.RawQuery = q.Encode()

		log.Info("Deleting JWT Token:", string(JWTApiKey))
		resp, err := client.Do(req)
		if err != nil {
			log.Error("Error in jwt api key DELETE", err)
			return false
		}
		defer resp.Body.Close()

		_, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Error("Error reading response body", err)
			return false
		}

		if resp.StatusCode == 200 {
			log.Info("Deleted JWT API Token")
		} else {
			log.Error("Error Creating JWT API Token")
			return false
		}
	}

	return true
}

func GetHTTPClient() (*retryablehttp.Client, bool) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	httpClient := &http.Client{Timeout: time.Second * 10, Transport: tr}

	client := retryablehttp.NewClient()
	client.HTTPClient = httpClient
	client.RetryMax = 3
	client.RetryWaitMin = 1 * time.Second
	client.RetryWaitMax = 30 * time.Second
	client.CheckRetry = checkRetry

	return client, true
}

func checkIfJwtKeyCreated(tykConf map[string]interface{}, jwtKey string, host string) bool {
	client, _ := GetHTTPClient()

	var endPoint = getTykEndpoint(host, TykJWTAPIKeyEndpoint) + jwtKey

	req, err := retryablehttp.NewRequest("GET", endPoint, nil)
	if err != nil {
		log.Error("Error creating GET reuest", err)
		return false
	}

	req.Header.Add("x-tyk-authorization", tykConf["secret"].(string))
	log.Info("Checking if JWT Token present: ", jwtKey)
	resp, err := client.Do(req)
	if err != nil {
		log.Error("Error creating GET reuest", err)
		return false
	}
	defer resp.Body.Close()

	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error("Error creating GET reuest", err)
		return false
	}

	if resp.StatusCode == 200 {
		log.Info("JWT Token found!")
	} else {
		log.Error("Could not find JWT Token")
		return false
	}

	return true
}

func checkRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
	// do not retry on context.Canceled or context.DeadlineExceeded
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if err != nil {
		return true, err
	}
	if resp.StatusCode != 200 {
		return true, nil
	}

	return false, nil
}

func deleteAPIById(apiID string) (interface{}, int) {
	c := GetRedisConn()
	defer c.Close()

	// Load API Definition from Redis DB
	apiData, err := redis.String(c.Do("GET", apiID))
	if err != nil {
		log.Warning("API does not exists ", err)
		return apiError("Api does not exists"), http.StatusInternalServerError
	}

	// Load API Definition from Redis DB
	_, err = c.Do("DEL", apiID)
	if err != nil {
		log.Warning("Error deleting API ", err)
		return apiError("Delete failed"), http.StatusInternalServerError
	}

	//Also delete the middleware folder if it was created
	mwFolder := TykMiddlewareRoot + "/" + TykBundles + "/" + apiID + "_" + TykMiddlewareBundleNameHash
	log.Info("Deleting API folder", mwFolder)
	err = os.RemoveAll(mwFolder)
	if err != nil {
		log.Warn("Error deleting bundle folder", err)
	}

	//remove api id from all JWT keys
	//TODO - Read appName from apiData and pass it to
	apiDef := &apidef.APIDefinition{}
	if err := json.NewDecoder(strings.NewReader(apiData)).Decode(apiDef); err != nil {
		return apiError("Could not decode api definition"), http.StatusInternalServerError
	}

	err = addOrDeleteJWTKey(DELETE, apiDef.AppName)
	if err != nil {
		log.Error("Error updating JWT keys", err)
		return apiError("Error updating JWT keys"), http.StatusInternalServerError
	}

	response := apiModifyKeySuccess{
		Key:    apiID,
		Status: "ok",
		Action: "deleted",
	}

	reloadURLStructure(nil)

	return response, http.StatusOK
}

func deleteAPIByService(service string) (interface{}, int) {
	var existingApis ServiceAPIS
	var apiData string

	c := GetRedisConn()

	log.Info("Deleting API from redis for service: ", service)

	defer c.Close()

	// Load API Definition from Redis DB
	keys, err := redis.Strings(c.Do("KEYS", service+"-*"))
	if err != nil {
		log.Warning("API does not exists ", err)
		return apiError("Api does not exists"), http.StatusInternalServerError
	}

	for pos, apiID := range keys {
		if pos == 0 {
			apiData, err = redis.String(c.Do("GET", apiID))
			if err != nil {
				log.Warning("Error getting API data ", err)
				return apiError("Delete failed"), http.StatusInternalServerError
			}
		}
		// Load API Definition from Redis DB
		log.Warning("Deleting API ", apiID)
		_, err = c.Do("DEL", apiID)
		if err != nil {
			log.Warning("Error deleting API ", err)
			return apiError("Delete failed"), http.StatusInternalServerError
		}

		//Also delete the middleware folder if it was created
		mwFolder := TykMiddlewareRoot + "/" + TykBundles + "/" + apiID + "_" + TykMiddlewareBundleNameHash
		log.Info("Deleting API folder", mwFolder)
		err = os.RemoveAll(mwFolder)
		if err != nil {
			log.Warn("Error deleting bundle folder", err)
		}
	}

	//remove api id from all JWT keys
	//TODO - Read appName from api sepc and pass it
	apiDef := &apidef.APIDefinition{}
	if err := json.NewDecoder(strings.NewReader(apiData)).Decode(apiDef); err != nil {
		return apiError("Could not decode api definition"), http.StatusInternalServerError
	}
	err = addOrDeleteJWTKey(DELETE, apiDef.AppName)
	if err != nil {
		log.Error("Error updating JWT keys", err)
		return apiError("Error updating JWT keys"), http.StatusInternalServerError
	}

	response := apiModifyKeySuccess{
		Key:    service,
		Status: "ok",
		Action: "deleted",
	}

	// Delete service api entry from api_definitions.json
	apiDefinitions, err := ioutil.ReadFile(APIDefinitionRedis)
	if err != nil {
		return apiError("Could not read api_definitions.json file"), http.StatusInternalServerError
	}

	err = json.Unmarshal(apiDefinitions, &existingApis)
	if err != nil {
		log.Error("Couldn't decode existing API Definition object: ", err)
		return apiError("Malformed api_definitions.json"), http.StatusBadRequest
	}

	delete(existingApis, service)

	reloadURLStructure(nil)

	return response, http.StatusOK
}

func getInbandIP(SysConfPath string) (string, error) {

	type InBandNet struct {
		Subnet    string `yaml:"subnet"`
		Iface     string `yaml:"iface"`
		GatewayIP string `yaml:"gatewayIP"`
		IfaceIP   string `yaml:"ifaceIP"`
	}

	type Inband struct {
		InBandNetwork InBandNet `yaml:"inbandNetwork"`
	}

	var data Inband

	SysConfData, err := ioutil.ReadFile(SysConfPath)

	err = yaml.Unmarshal(SysConfData, &data)
	if err != nil {
		return "", err
	}

	return data.InBandNetwork.IfaceIP, nil
}

func RemoveDirContents(dir string) error {
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		d, err := os.Open(dir)
		if err != nil {
			return err
		}
		defer d.Close()
		names, err := d.Readdirnames(-1)
		if err != nil {
			return err
		}
		for _, name := range names {
			err = os.RemoveAll(filepath.Join(dir, name))
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func Contains(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

func copyFile(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	nBytes, err := io.Copy(destination, source)
	return nBytes, err
}

func getTykEndpoint(host string, path string) string {
	url := url.URL{
		Scheme: "https",
		Host:   host + ":" + strconv.Itoa(config.Global().ControlAPIPort),
		Path:   path,
	}
	return url.String()
}

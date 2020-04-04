package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"sync"
	"time"

	"github.com/TykTechnologies/tyk/config"
	"github.com/garyburd/redigo/redis"
	"github.com/gorilla/mux"
	"github.com/hashicorp/go-retryablehttp"
	"gopkg.in/yaml.v2"
)

//nolint
var (
	TykHTTPPort                  = "4430"
	TykJWTAPIKeyEndpoint         = "/tyk/keys/"
	TykMiddlewareBundleNameHash  = "c343271e0935000c0ea41f8d9822015c"
	TykBundles                   = "bundles"
	TykMiddlewareBundleName      = "bundle.zip"
	TykMiddlewareFile            = "middleware.py"
	TykManifest                  = "manifest.json"
	TykRoot                      = "/data/tyk-gateway/"
	TykCACert                    = "/certs/cacerts.crt"
	TykServerCrt                 = "/certs/server.crt"
	TykServerKey                 = "/certs/server.key"
	TykUpstreamPem               = "/certs/upstream.pem"
	SystemConfigFilePath         = "/data/config/systemconfig.yaml"
	TykMiddlewareRoot            = "/data/tyk-gateway/middleware/"
	TykMiddlewareSrcFile         = TykRoot + TykMiddlewareFile
	TykMiddlewareManifestSrcFile = TykRoot + TykManifest
	JWTDefinitionsSpec           = TykRoot + "/jwt_definition.json"
	TykConfFilePath              = TykRoot + "/tyk.conf"
	JWTApiKeySpec                = TykRoot + "/token_jwt.json"
	APITemplateOpenSpec          = TykRoot + "/api_template_open.json"
	APITemplateJWTSpec           = TykRoot + "/api_template_jwt.json"
	APIDefinitionRedis           = TykRoot + "/api_definitions.json"
	DynamicAPIConnTimeout        = 20000
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
}

// JWTDefinitions to store JWTDefinition
type JWTDefinition struct {
	Name             string `json:"name"`
	JWTPublicKeyPath string `json:"jwt_public_key_path"`
	JWTAPIKeyPath    string `json:"jwt_api_key_path"`
	JWTMinKeyLength  int    `json:"jwt_min_key_length"`
}

type ServiceAPIS map[string][]APIDefinition

// JWTDefinitions to store JWTDefinitions
type JWTDefinitions struct {
	JWTDefinitions []JWTDefinition `json:"jwt_definitions"`
}

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
		if r.URL.Path == "/key/refresh" {
			log.Debug("Key refresh")
			obj, code = updateKeys(ADD)
		} else if apiName == "" && service == "" {
			log.Debug("Creating new definition")
			obj, code = addOrUpdateApi(r)
		} else {
			obj, code = apiError("Can not Add/Update service specific APIs. Use /tyk/api or /tyk/key/refresh endpoint"), http.StatusBadRequest
		}
	case "DELETE":
		if apiName != "" && service != "" {
			log.Info("Deleting Individual API not supported")
			//obj, code = deleteAPIById(apiID)
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

func updateKeys(e Event) (interface{}, int) {
	err := addOrDeleteJWTKey(ADD)
	if err != nil {
		return apiError("Could not update api key"), http.StatusInternalServerError
	}

	response := apiModifyKeySuccess{
		Status: "ok",
		Action: "updated",
	}

	return response, http.StatusOK
}

func addOrUpdateApi(r *http.Request) (interface{}, int) {
	connTimeout := DynamicAPIConnTimeout
	log.Info("Updating/Adding API to redis")
	c := GetRedisConn()
	defer c.Close()

	if config.Global().UseDBAppConfigs {
		log.Error("Rejected new API Definition due to UseDBAppConfigs = true")
		return apiError("Due to enabled use_db_app_configs, please use the Dashboard API"), http.StatusInternalServerError
	}

	if config.Global().DynamicAPIConnTimeout == 0 {
		connTimeout = DynamicAPIConnTimeout
	} else {
		connTimeout = config.Global().DynamicAPIConnTimeout
	}

	var ServApis ServiceAPIS
	var existingApis ServiceAPIS

	// Non blocking read or wait for 20 seconds in idle state
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
			return apiError("Request malformed"), http.StatusInternalServerError
		}

		t := time.Now()
		elapsed := t.Sub(start)

		if elapsed.Nanoseconds()/1000000 > int64(connTimeout) {
			log.Error("request timed out")
			return apiError("Request timedout"), http.StatusInternalServerError
		}
		time.Sleep(2 * time.Millisecond)
	}
	log.Debug("Received data length : ", count)

	err := json.Unmarshal(data, &ServApis)
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
	err = addOrDeleteJWTKey(ADD)
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

func addOrDeleteJWTKey(e Event) error {
	var JWTAPIMap = make(map[string]string)
	//c := RedisPool.Get()
	c := GetRedisConn()
	defer c.Close()

	apis, err := redis.Strings(c.Do("KEYS", "*"))
	if err != nil {
		log.Error("Could not get API list from Redis", err)
		return err
	}

	for _, api := range apis {
		data, err := redis.String(c.Do("GET", api))
		if err != nil {
			log.Error("Error reading API from Redis", err)
			return err
		}

		var jsonApi map[string]interface{}
		err = json.Unmarshal([]byte(data), &jsonApi)

		if jsonApi["enable_jwt"] == true {
			apiID := jsonApi["api_id"].(string)
			name := jsonApi["name"].(string)
			JWTAPIMap[apiID] = name
		}
	}
	log.Debug("JWT API Map", JWTAPIMap)

	// If there are other JWT API enabled APIs
	//Add JWT KEY - go over JWT Definition, add and update all Keys
	var jwtDefinitions JWTDefinitions
	var tykConf map[string]interface{}

	data, err := ioutil.ReadFile(JWTDefinitionsSpec)
	if err != nil {
		log.Error("Error reading JWT Spec", err)
		return err
	}

	err = json.Unmarshal(data, &jwtDefinitions)
	if err != nil {
		log.Error("Error decoding JWT Spec", err)
		return err
	}

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

	for _, jwtMeta := range jwtDefinitions.JWTDefinitions {
		count := 0
		for {
			time.Sleep(2 * time.Second)
			ret := processJWTApiKey(tykConf, JWTAPIMap, jwtMeta.JWTPublicKeyPath, jwtMeta.JWTAPIKeyPath, "localhost", e)
			count++
			if ret == true {
				break
			} else if count < 3 {
				log.Warn("Could not verify JWT API Token.. retry")
			} else {
				log.Error("Could not add JWT token", jwtMeta.JWTAPIKeyPath)
				break
			}
		}
	}
	return nil
}

func processJWTApiKey(tykConf map[string]interface{},
	jwtAPIMap map[string]string, jwtPublicKeyPath string, jwtAPIKeyPath string,
	host string, e Event) bool {

	var APIList = make(map[string]TokenAccessRights)
	var template map[string]interface{}

	//Read JWT Public key
	JWTPublicKey, err := ioutil.ReadFile(jwtPublicKeyPath)
	if err != nil {
		log.Error("Error Reading jwt public key")
		return false
	}

	//Read JWT API Key
	//TODO - Add retry flow if key is missing
	JWTApiKey, err := ioutil.ReadFile(jwtAPIKeyPath)
	if err != nil {
		log.Error("Error Reading jwt private key")
		return false
	}

	for key, value := range jwtAPIMap {
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
	if (e == ADD && len(jwtAPIMap) > 0) || (e == DELETE && len(jwtAPIMap) > 0) {
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
	} else if e == DELETE && len(jwtAPIMap) == 0 {
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
	_, err := redis.String(c.Do("GET", apiID))
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
	err = addOrDeleteJWTKey(DELETE)
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

	//c := RedisPool.Get()
	c := GetRedisConn()

	log.Info("Deleting API from redis for service: ", service)

	defer c.Close()

	// Load API Definition from Redis DB
	keys, err := redis.Strings(c.Do("KEYS", service+"-*"))
	if err != nil {
		log.Warning("API does not exists ", err)
		return apiError("Api does not exists"), http.StatusInternalServerError
	}

	for _, apiID := range keys {
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
	}

	//remove api id from all JWT keys
	err = addOrDeleteJWTKey(DELETE)
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
		Host:   host + ":" + TykHTTPPort,
		Path:   path,
	}
	return url.String()
}

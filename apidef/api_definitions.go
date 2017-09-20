package apidef

import (
	"encoding/base64"

	"github.com/lonelycode/osin"
	"gopkg.in/mgo.v2/bson"
)

type AuthProviderCode string
type SessionProviderCode string
type StorageEngineCode string
type TykEvent string            // A type so we can ENUM event types easily, e.g. EventQuotaExceeded
type TykEventHandlerName string // A type for handler codes in API definitions

type EndpointMethodAction string
type TemplateMode string

type MiddlewareDriver string
type IdExtractorSource string
type IdExtractorType string
type AuthTypeEnum string

const (
	NoAction EndpointMethodAction = "no_action"
	Reply    EndpointMethodAction = "reply"

	UseBlob TemplateMode = "blob"
	UseFile TemplateMode = "file"

	RequestXML  RequestInputType = "xml"
	RequestJSON RequestInputType = "json"

	OttoDriver   MiddlewareDriver = "otto"
	PythonDriver MiddlewareDriver = "python"
	LuaDriver    MiddlewareDriver = "lua"
	GrpcDriver   MiddlewareDriver = "grpc"

	BodySource        IdExtractorSource = "body"
	HeaderSource      IdExtractorSource = "header"
	QuerystringSource IdExtractorSource = "querystring"
	FormSource        IdExtractorSource = "form"

	ValueExtractor IdExtractorType = "value"
	XPathExtractor IdExtractorType = "xpath"
	RegexExtractor IdExtractorType = "regex"

	// For multi-type auth
	AuthToken     AuthTypeEnum = "auth_token"
	HMACKey       AuthTypeEnum = "hmac_key"
	BasicAuthUser AuthTypeEnum = "basic_auth_user"
	JWTClaim      AuthTypeEnum = "jwt_claim"
	OIDCUser      AuthTypeEnum = "oidc_user"
	OAuthKey      AuthTypeEnum = "oauth_key"
	UnsetAuth     AuthTypeEnum = ""
)

type EndpointMethodMeta struct {
	Action  EndpointMethodAction `bson:"action" json:"action"`
	Code    int                  `bson:"code" json:"code"`
	Data    string               `bson:"data" json:"data"`
	Headers map[string]string    `bson:"headers" json:"headers"`
}

type EndPointMeta struct {
	Path          string                        `bson:"path" json:"path"`
	MethodActions map[string]EndpointMethodMeta `bson:"method_actions" json:"method_actions"`
}

type RequestInputType string

type TemplateMeta struct {
	TemplateData struct {
		Input          RequestInputType `bson:"input_type" json:"input_type"`
		Mode           TemplateMode     `bson:"template_mode" json:"template_mode"`
		EnableSession  bool             `bson:"enable_session" json:"enable_session"`
		TemplateSource string           `bson:"template_source" json:"template_source"`
	} `bson:"template_data" json:"template_data"`
	Path   string `bson:"path" json:"path"`
	Method string `bson:"method" json:"method"`
}

type HeaderInjectionMeta struct {
	DeleteHeaders []string          `bson:"delete_headers" json:"delete_headers"`
	AddHeaders    map[string]string `bson:"add_headers" json:"add_headers"`
	Path          string            `bson:"path" json:"path"`
	Method        string            `bson:"method" json:"method"`
	ActOnResponse bool              `bson:"act_on" json:"act_on"`
}

type HardTimeoutMeta struct {
	Path    string `bson:"path" json:"path"`
	Method  string `bson:"method" json:"method"`
	TimeOut int    `bson:"timeout" json:"timeout"`
}

type TrackEndpointMeta struct {
	Path   string `bson:"path" json:"path"`
	Method string `bson:"method" json:"method"`
}

type RequestSizeMeta struct {
	Path      string `bson:"path" json:"path"`
	Method    string `bson:"method" json:"method"`
	SizeLimit int64  `bson:"size_limit" json:"size_limit"`
}

type CircuitBreakerMeta struct {
	Path                 string  `bson:"path" json:"path"`
	Method               string  `bson:"method" json:"method"`
	ThresholdPercent     float64 `bson:"threshold_percent" json:"threshold_percent"`
	Samples              int64   `bson:"samples" json:"samples"`
	ReturnToServiceAfter int     `bson:"return_to_service_after" json:"return_to_service_after"`
}

type URLRewriteMeta struct {
	Path         string `bson:"path" json:"path"`
	Method       string `bson:"method" json:"method"`
	MatchPattern string `bson:"match_pattern" json:"match_pattern"`
	RewriteTo    string `bson:"rewrite_to" json:"rewrite_to"`
}

type VirtualMeta struct {
	ResponseFunctionName string `bson:"response_function_name" json:"response_function_name"`
	FunctionSourceType   string `bson:"function_source_type" json:"function_source_type"`
	FunctionSourceURI    string `bson:"function_source_uri" json:"function_source_uri"`
	Path                 string `bson:"path" json:"path"`
	Method               string `bson:"method" json:"method"`
	UseSession           bool   `bson:"use_session" json:"use_session"`
}

type MethodTransformMeta struct {
	Path     string `bson:"path" json:"path"`
	Method   string `bson:"method" json:"method"`
	ToMethod string `bson:"to_method" json:"to_method"`
}

type ExtendedPathsSet struct {
	Ignored                 []EndPointMeta        `bson:"ignored" json:"ignored,omitempty"`
	WhiteList               []EndPointMeta        `bson:"white_list" json:"white_list,omitempty"`
	BlackList               []EndPointMeta        `bson:"black_list" json:"black_list,omitempty"`
	Cached                  []string              `bson:"cache" json:"cache,omitempty"`
	Transform               []TemplateMeta        `bson:"transform" json:"transform,omitempty"`
	TransformResponse       []TemplateMeta        `bson:"transform_response" json:"transform_response,omitempty"`
	TransformHeader         []HeaderInjectionMeta `bson:"transform_headers" json:"transform_headers,omitempty"`
	TransformResponseHeader []HeaderInjectionMeta `bson:"transform_response_headers" json:"transform_response_headers,omitempty"`
	HardTimeouts            []HardTimeoutMeta     `bson:"hard_timeouts" json:"hard_timeouts,omitempty"`
	CircuitBreaker          []CircuitBreakerMeta  `bson:"circuit_breakers" json:"circuit_breakers,omitempty"`
	URLRewrite              []URLRewriteMeta      `bson:"url_rewrites" json:"url_rewrites,omitempty"`
	Virtual                 []VirtualMeta         `bson:"virtual" json:"virtual,omitempty"`
	SizeLimit               []RequestSizeMeta     `bson:"size_limits" json:"size_limits,omitempty"`
	MethodTransforms        []MethodTransformMeta `bson:"method_transforms" json:"method_transforms,omitempty"`
	TrackEndpoints          []TrackEndpointMeta   `bson:"track_endpoints" json:"track_endpoints,omitempty"`
	DoNotTrackEndpoints     []TrackEndpointMeta   `bson:"do_not_track_endpoints" json:"do_not_track_endpoints,omitempty"`
}

type VersionInfo struct {
	Name    string `bson:"name" json:"name"`
	Expires string `bson:"expires" json:"expires"`
	Paths   struct {
		Ignored   []string `bson:"ignored" json:"ignored"`
		WhiteList []string `bson:"white_list" json:"white_list"`
		BlackList []string `bson:"black_list" json:"black_list"`
	} `bson:"paths" json:"paths"`
	UseExtendedPaths    bool              `bson:"use_extended_paths" json:"use_extended_paths"`
	ExtendedPaths       ExtendedPathsSet  `bson:"extended_paths" json:"extended_paths"`
	GlobalHeaders       map[string]string `bson:"global_headers" json:"global_headers"`
	GlobalHeadersRemove []string          `bson:"global_headers_remove" json:"global_headers_remove"`
	GlobalSizeLimit     int64             `bson:"global_size_limit" json:"global_size_limit"`
	OverrideTarget      string            `bson:"override_target" json:"override_target"`
}

type AuthProviderMeta struct {
	Name          AuthProviderCode       `bson:"name" json:"name"`
	StorageEngine StorageEngineCode      `bson:"storage_engine" json:"storage_engine"`
	Meta          map[string]interface{} `bson:"meta" json:"meta"`
}

type SessionProviderMeta struct {
	Name          SessionProviderCode    `bson:"name" json:"name"`
	StorageEngine StorageEngineCode      `bson:"storage_engine" json:"storage_engine"`
	Meta          map[string]interface{} `bson:"meta" json:"meta"`
}

type EventHandlerTriggerConfig struct {
	Handler     TykEventHandlerName    `bson:"handler_name" json:"handler_name"`
	HandlerMeta map[string]interface{} `bson:"handler_meta" json:"handler_meta"`
}

type EventHandlerMetaConfig struct {
	Events map[TykEvent][]EventHandlerTriggerConfig `bson:"events" json:"events"`
}

type MiddlewareDefinition struct {
	Name           string `bson:"name" json:"name"`
	Path           string `bson:"path" json:"path"`
	RequireSession bool   `bson:"require_session" json:"require_session"`
}

type MiddlewareIdExtractor struct {
	ExtractFrom     IdExtractorSource      `bson:"extract_from" json:"extract_from"`
	ExtractWith     IdExtractorType        `bson:"extract_with" json:"extract_with"`
	ExtractorConfig map[string]interface{} `bson:"extractor_config" json:"extractor_config"`
	Extractor       interface{}            `bson:"-" json:"-"`
}

type MiddlewareSection struct {
	Pre         []MiddlewareDefinition `bson:"pre" json:"pre"`
	Post        []MiddlewareDefinition `bson:"post" json:"post"`
	PostKeyAuth []MiddlewareDefinition `bson:"post_key_auth" json:"post_key_auth"`
	AuthCheck   MiddlewareDefinition   `bson:"auth_check" json:"auth_check"`
	Response    []MiddlewareDefinition `bson:"response" json:"response"`
	Driver      MiddlewareDriver       `bson:"driver" json:"driver"`
	IdExtractor MiddlewareIdExtractor  `bson:"id_extractor" json:"id_extractor"`
}

type CacheOptions struct {
	CacheTimeout               int64 `bson:"cache_timeout" json:"cache_timeout"`
	EnableCache                bool  `bson:"enable_cache" json:"enable_cache"`
	CacheAllSafeRequests       bool  `bson:"cache_all_safe_requests" json:"cache_all_safe_requests"`
	CacheOnlyResponseCodes     []int `bson:"cache_response_codes" json:"cache_response_codes"`
	EnableUpstreamCacheControl bool  `bson:"enable_upstream_cache_control" json:"enable_upstream_cache_control"`
}

type ResponseProcessor struct {
	Name    string      `bson:"name" json:"name"`
	Options interface{} `bson:"options" json:"options"`
}

type HostCheckObject struct {
	CheckURL string            `bson:"url" json:"url"`
	Method   string            `bson:"method" json:"method"`
	Headers  map[string]string `bson:"headers" json:"headers"`
	Body     string            `bson:"body" json:"body"`
}

type ServiceDiscoveryConfiguration struct {
	UseDiscoveryService bool   `bson:"use_discovery_service" json:"use_discovery_service"`
	QueryEndpoint       string `bson:"query_endpoint" json:"query_endpoint"`
	UseNestedQuery      bool   `bson:"use_nested_query" json:"use_nested_query"`
	ParentDataPath      string `bson:"parent_data_path" json:"parent_data_path"`
	DataPath            string `bson:"data_path" json:"data_path"`
	PortDataPath        string `bson:"port_data_path" json:"port_data_path"`
	TargetPath          string `bson:"target_path" json:"target_path"`
	UseTargetList       bool   `bson:"use_target_list" json:"use_target_list"`
	CacheTimeout        int64  `bson:"cache_timeout" json:"cache_timeout"`
	EndpointReturnsList bool   `bson:"endpoint_returns_list" json:"endpoint_returns_list"`
}

type OIDProviderConfig struct {
	Issuer    string            `bson:"issuer" json:"issuer"`
	ClientIDs map[string]string `bson:"client_ids" json:"client_ids"`
}

type OpenIDOptions struct {
	Providers         []OIDProviderConfig `bson:"providers" json:"providers"`
	SegregateByClient bool                `bson:"segregate_by_client" json:"segregate_by_client"`
}

// APIDefinition represents the configuration for a single proxied API and it's versions.
type APIDefinition struct {
	Id               bson.ObjectId `bson:"_id,omitempty" json:"id,omitempty"`
	Name             string        `bson:"name" json:"name"`
	Slug             string        `bson:"slug" json:"slug"`
	APIID            string        `bson:"api_id" json:"api_id"`
	OrgID            string        `bson:"org_id" json:"org_id"`
	UseKeylessAccess bool          `bson:"use_keyless" json:"use_keyless"`
	UseOauth2        bool          `bson:"use_oauth2" json:"use_oauth2"`
	UseOpenID        bool          `bson:"use_openid" json:"use_openid"`
	OpenIDOptions    OpenIDOptions `bson:"openid_options" json:"openid_options"`
	Oauth2Meta       struct {
		AllowedAccessTypes     []osin.AccessRequestType    `bson:"allowed_access_types" json:"allowed_access_types"`
		AllowedAuthorizeTypes  []osin.AuthorizeRequestType `bson:"allowed_authorize_types" json:"allowed_authorize_types"`
		AuthorizeLoginRedirect string                      `bson:"auth_login_redirect" json:"auth_login_redirect"`
	} `bson:"oauth_meta" json:"oauth_meta"`
	Auth struct {
		UseParam       bool   `mapstructure:"use_param" bson:"use_param" json:"use_param"`
		ParamName      string `mapstructure:"param_name" bson:"param_name" json:"param_name"`
		UseCookie      bool   `mapstructure:"use_cookie" bson:"use_cookie" json:"use_cookie"`
		CookieName     string `mapstructure:"cookie_name" bson:"cookie_name" json:"cookie_name"`
		AuthHeaderName string `mapstructure:"auth_header_name" bson:"auth_header_name" json:"auth_header_name"`
	} `bson:"auth" json:"auth"`
	UseBasicAuth            bool                 `bson:"use_basic_auth" json:"use_basic_auth"`
	EnableJWT               bool                 `bson:"enable_jwt" json:"enable_jwt"`
	UseStandardAuth         bool                 `bson:"use_standard_auth" json:"use_standard_auth"`
	EnableCoProcessAuth     bool                 `bson:"enable_coprocess_auth" json:"enable_coprocess_auth"`
	JWTSigningMethod        string               `bson:"jwt_signing_method" json:"jwt_signing_method"`
	JWTSource               string               `bson:"jwt_source" json:"jwt_source"`
	JWTIdentityBaseField    string               `bson:"jwt_identit_base_field" json:"jwt_identity_base_field"`
	JWTClientIDBaseField    string               `bson:"jwt_client_base_field" json:"jwt_client_base_field"`
	JWTPolicyFieldName      string               `bson:"jwt_policy_field_name" json:"jwt_policy_field_name"`
	NotificationsDetails    NotificationsManager `bson:"notifications" json:"notifications"`
	EnableSignatureChecking bool                 `bson:"enable_signature_checking" json:"enable_signature_checking"`
	HmacAllowedClockSkew    float64              `bson:"hmac_allowed_clock_skew" json:"hmac_allowed_clock_skew"`
	BaseIdentityProvidedBy  AuthTypeEnum         `bson:"base_identity_provided_by" json:"base_identity_provided_by"`
	VersionDefinition       struct {
		Location string `bson:"location" json:"location"`
		Key      string `bson:"key" json:"key"`
	} `bson:"definition" json:"definition"`
	VersionData struct {
		NotVersioned bool                   `bson:"not_versioned" json:"not_versioned"`
		Versions     map[string]VersionInfo `bson:"versions" json:"versions"`
	} `bson:"version_data" json:"version_data"`
	UptimeTests struct {
		CheckList []HostCheckObject `bson:"check_list" json:"check_list"`
		Config    struct {
			ExpireUptimeAnalyticsAfter int64                         `bson:"expire_utime_after" json:"expire_utime_after"` // must have an expireAt TTL index set (http://docs.mongodb.org/manual/tutorial/expire-data/)
			ServiceDiscovery           ServiceDiscoveryConfiguration `bson:"service_discovery" json:"service_discovery"`
			RecheckWait                int                           `bson:"recheck_wait" json:"recheck_wait"`
		} `bson:"config" json:"config"`
	} `bson:"uptime_tests" json:"uptime_tests"`
	Proxy struct {
		PreserveHostHeader          bool                          `bson:"preserve_host_header" json:"preserve_host_header"`
		ListenPath                  string                        `bson:"listen_path" json:"listen_path"`
		TargetURL                   string                        `bson:"target_url" json:"target_url"`
		StripListenPath             bool                          `bson:"strip_listen_path" json:"strip_listen_path"`
		EnableLoadBalancing         bool                          `bson:"enable_load_balancing" json:"enable_load_balancing"`
		Targets                     []string                      `bson:"target_list" json:"target_list"`
		StructuredTargetList        *HostList                     `bson:"-" json:"-"`
		CheckHostAgainstUptimeTests bool                          `bson:"check_host_against_uptime_tests" json:"check_host_against_uptime_tests"`
		ServiceDiscovery            ServiceDiscoveryConfiguration `bson:"service_discovery" json:"service_discovery"`
	} `bson:"proxy" json:"proxy"`
	DisableRateLimit          bool                   `bson:"disable_rate_limit" json:"disable_rate_limit"`
	DisableQuota              bool                   `bson:"disable_quota" json:"disable_quota"`
	CustomMiddleware          MiddlewareSection      `bson:"custom_middleware" json:"custom_middleware"`
	CustomMiddlewareBundle    string                 `bson:"custom_middleware_bundle" json:"custom_middleware_bundle"`
	CacheOptions              CacheOptions           `bson:"cache_options" json:"cache_options"`
	SessionLifetime           int64                  `bson:"session_lifetime" json:"session_lifetime"`
	Active                    bool                   `bson:"active" json:"active"`
	AuthProvider              AuthProviderMeta       `bson:"auth_provider" json:"auth_provider"`
	SessionProvider           SessionProviderMeta    `bson:"session_provider" json:"session_provider"`
	EventHandlers             EventHandlerMetaConfig `bson:"event_handlers" json:"event_handlers"`
	EnableBatchRequestSupport bool                   `bson:"enable_batch_request_support" json:"enable_batch_request_support"`
	EnableIpWhiteListing      bool                   `mapstructure:"enable_ip_whitelisting" bson:"enable_ip_whitelisting" json:"enable_ip_whitelisting"`
	AllowedIPs                []string               `mapstructure:"allowed_ips" bson:"allowed_ips" json:"allowed_ips"`
	DontSetQuotasOnCreate     bool                   `mapstructure:"dont_set_quota_on_create" bson:"dont_set_quota_on_create" json:"dont_set_quota_on_create"`
	ExpireAnalyticsAfter      int64                  `mapstructure:"expire_analytics_after" bson:"expire_analytics_after" json:"expire_analytics_after"` // must have an expireAt TTL index set (http://docs.mongodb.org/manual/tutorial/expire-data/)
	ResponseProcessors        []ResponseProcessor    `bson:"response_processors" json:"response_processors"`
	CORS                      struct {
		Enable             bool     `bson:"enable" json:"enable"`
		AllowedOrigins     []string `bson:"allowed_origins" json:"allowed_origins"`
		AllowedMethods     []string `bson:"allowed_methods" json:"allowed_methods"`
		AllowedHeaders     []string `bson:"allowed_headers" json:"allowed_headers"`
		ExposedHeaders     []string `bson:"exposed_headers" json:"exposed_headers"`
		AllowCredentials   bool     `bson:"allow_credentials" json:"allow_credentials"`
		MaxAge             int      `bson:"max_age" json:"max_age"`
		OptionsPassthrough bool     `bson:"options_passthrough" json:"options_passthrough"`
		Debug              bool     `bson:"debug" json:"debug"`
	} `bson:"CORS" json:"CORS"`
	Domain            string                 `bson:"domain" json:"domain"`
	DoNotTrack        bool                   `bson:"do_not_track" json:"do_not_track"`
	Tags              []string               `bson:"tags" json:"tags"`
	EnableContextVars bool                   `bson:"enable_context_vars" json:"enable_context_vars"`
	ConfigData        map[string]interface{} `bson:"config_data" json:"config_data"`
	TagHeaders        map[string]interface{} `bson:"tag_headers" json:"tag_headers"`
	GlobalRateLimit   GlobalRateLimit        `bson:"global_rate_limit" json:"global_rate_limit"`
}

type GlobalRateLimit struct {
	Rate float64 `bson:"rate" json:"rate"`
	Per  float64 `bson:"per" json:"per"`
}

type BundleManifest struct {
	FileList         []string          `bson:"file_list" json:"file_list"`
	CustomMiddleware MiddlewareSection `bson:"custom_middleware" json:"custom_middleware"`
	Checksum         string            `bson:"checksum" json:"checksum"`
	Signature        string            `bson:"signature" json:"signature"`
}

// Clean will URL encode map[string]struct variables for saving
func (a *APIDefinition) EncodeForDB() {
	new_version := make(map[string]VersionInfo)
	for k, v := range a.VersionData.Versions {
		newK := base64.StdEncoding.EncodeToString([]byte(k))
		v.Name = newK
		new_version[newK] = v
	}

	a.VersionData.Versions = new_version
}

func (a *APIDefinition) DecodeFromDB() {
	new_version := make(map[string]VersionInfo)
	for k, v := range a.VersionData.Versions {
		newK, err := base64.StdEncoding.DecodeString(k)
		if err != nil {
			log.Error("Couldn't Decode, leaving as it may be legacy...")
			new_version[k] = v
		} else {
			v.Name = string(newK)
			new_version[string(newK)] = v
		}
	}

	a.VersionData.Versions = new_version
}

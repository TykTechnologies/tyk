package apidef

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"net/http"
	"text/template"
	"time"

	"github.com/TykTechnologies/storage/persistent/model"

	"github.com/clbanning/mxj"
	"github.com/lonelycode/osin"

	"github.com/TykTechnologies/tyk/internal/reflect"

	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/kafka_datasource"
	"github.com/TykTechnologies/graphql-go-tools/pkg/execution/datasource"

	"github.com/TykTechnologies/gojsonschema"
	"github.com/TykTechnologies/tyk/regexp"

	"github.com/TykTechnologies/tyk/internal/uuid"
)

type AuthProviderCode string
type SessionProviderCode string
type StorageEngineCode string
type TykEvent string            // A type so we can ENUM event types easily, e.g. EventQuotaExceeded
type TykEventHandlerName string // A type for handler codes in API definitions

type EndpointMethodAction string
type SourceMode string

type MiddlewareDriver string
type IdExtractorSource string
type IdExtractorType string
type AuthTypeEnum string
type RoutingTriggerOnType string

type SubscriptionType string

type IDExtractor interface{}

const (
	NoAction EndpointMethodAction = "no_action"
	Reply    EndpointMethodAction = "reply"

	UseBlob SourceMode = "blob"
	UseFile SourceMode = "file"

	RequestXML  RequestInputType = "xml"
	RequestJSON RequestInputType = "json"

	OttoDriver     MiddlewareDriver = "otto"
	PythonDriver   MiddlewareDriver = "python"
	LuaDriver      MiddlewareDriver = "lua"
	GrpcDriver     MiddlewareDriver = "grpc"
	GoPluginDriver MiddlewareDriver = "goplugin"

	BodySource        IdExtractorSource = "body"
	HeaderSource      IdExtractorSource = "header"
	QuerystringSource IdExtractorSource = "querystring"
	FormSource        IdExtractorSource = "form"

	ValueExtractor IdExtractorType = "value"
	XPathExtractor IdExtractorType = "xpath"
	RegexExtractor IdExtractorType = "regex"

	// For multi-type auth
	AuthTypeNone  AuthTypeEnum = ""
	AuthToken     AuthTypeEnum = "auth_token"
	CustomAuth    AuthTypeEnum = "custom_auth"
	HMACKey       AuthTypeEnum = "hmac_key"
	BasicAuthUser AuthTypeEnum = "basic_auth_user"
	JWTClaim      AuthTypeEnum = "jwt_claim"
	OIDCUser      AuthTypeEnum = "oidc_user"
	OAuthKey      AuthTypeEnum = "oauth_key"
	UnsetAuth     AuthTypeEnum = ""

	// For routing triggers
	All    RoutingTriggerOnType = "all"
	Any    RoutingTriggerOnType = "any"
	Ignore RoutingTriggerOnType = ""

	// Subscription Types
	GQLSubscriptionUndefined   SubscriptionType = ""
	GQLSubscriptionWS          SubscriptionType = "graphql-ws"
	GQLSubscriptionTransportWS SubscriptionType = "graphql-transport-ws"
	GQLSubscriptionSSE         SubscriptionType = "sse"

	// TykInternalApiHeader - flags request as internal api looping request
	TykInternalApiHeader = "x-tyk-internal"

	HeaderLocation       = "header"
	URLParamLocation     = "url-param"
	URLLocation          = "url"
	ExpirationTimeFormat = "2006-01-02 15:04"

	Self                 = "self"
	DefaultAPIVersionKey = "x-api-version"
	HeaderBaseAPIID      = "x-tyk-base-api-id"

	AuthTokenType     = "authToken"
	JWTType           = "jwt"
	HMACType          = "hmac"
	BasicType         = "basic"
	CoprocessType     = "coprocess"
	OAuthType         = "oauth"
	ExternalOAuthType = "externalOAuth"
	OIDCType          = "oidc"
)

var (
	ErrAPIMigrated                = errors.New("the supplied API definition is in Tyk classic format, please use OAS format for this API")
	ErrAPINotMigrated             = errors.New("the supplied API definition is in OAS format, please use the Tyk classic format for this API")
	ErrOASGetForOldAPI            = errors.New("the requested API definition is in Tyk classic format, please use old api endpoint")
	ErrImportWithTykExtension     = errors.New("the import payload should not contain x-tyk-api-gateway")
	ErrPayloadWithoutTykExtension = errors.New("the payload should contain x-tyk-api-gateway")
	ErrAPINotFound                = errors.New("API not found")
	ErrMissingAPIID               = errors.New("missing API ID")
)

type EndpointMethodMeta struct {
	Action  EndpointMethodAction `bson:"action" json:"action"`
	Code    int                  `bson:"code" json:"code"`
	Data    string               `bson:"data" json:"data"`
	Headers map[string]string    `bson:"headers" json:"headers"`
}

type MockResponseMeta struct {
	Disabled   bool              `bson:"disabled" json:"disabled"`
	Path       string            `bson:"path" json:"path"`
	Method     string            `bson:"method" json:"method"`
	IgnoreCase bool              `bson:"ignore_case" json:"ignore_case"`
	Code       int               `bson:"code" json:"code"`
	Body       string            `bson:"body" json:"body"`
	Headers    map[string]string `bson:"headers" json:"headers"`
}

type EndPointMeta struct {
	Disabled   bool   `bson:"disabled" json:"disabled"`
	Path       string `bson:"path" json:"path"`
	Method     string `bson:"method" json:"method"`
	IgnoreCase bool   `bson:"ignore_case" json:"ignore_case"`
	// Deprecated. Use Method instead.
	MethodActions map[string]EndpointMethodMeta `bson:"method_actions,omitempty" json:"method_actions,omitempty"`
}

type CacheMeta struct {
	Disabled               bool   `bson:"disabled" json:"disabled"`
	Method                 string `bson:"method" json:"method"`
	Path                   string `bson:"path" json:"path"`
	CacheKeyRegex          string `bson:"cache_key_regex" json:"cache_key_regex"`
	CacheOnlyResponseCodes []int  `bson:"cache_response_codes" json:"cache_response_codes"`
}

type RequestInputType string

type TemplateData struct {
	Input          RequestInputType `bson:"input_type" json:"input_type"`
	Mode           SourceMode       `bson:"template_mode" json:"template_mode"`
	EnableSession  bool             `bson:"enable_session" json:"enable_session"`
	TemplateSource string           `bson:"template_source" json:"template_source"`
}

type TemplateMeta struct {
	Disabled     bool         `bson:"disabled" json:"disabled"`
	TemplateData TemplateData `bson:"template_data" json:"template_data"`
	Path         string       `bson:"path" json:"path"`
	Method       string       `bson:"method" json:"method"`
}

type TransformJQMeta struct {
	Filter string `bson:"filter" json:"filter"`
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
	Disabled bool   `bson:"disabled" json:"disabled"`
	Path     string `bson:"path" json:"path"`
	Method   string `bson:"method" json:"method"`
	TimeOut  int    `bson:"timeout" json:"timeout"`
}

type TrackEndpointMeta struct {
	Path   string `bson:"path" json:"path"`
	Method string `bson:"method" json:"method"`
}

type InternalMeta struct {
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
	DisableHalfOpenState bool    `bson:"disable_half_open_state" json:"disable_half_open_state"`
}

type StringRegexMap struct {
	MatchPattern string `bson:"match_rx" json:"match_rx"`
	Reverse      bool   `bson:"reverse" json:"reverse"`
	matchRegex   *regexp.Regexp
}

type RoutingTriggerOptions struct {
	HeaderMatches         map[string]StringRegexMap `bson:"header_matches" json:"header_matches"`
	QueryValMatches       map[string]StringRegexMap `bson:"query_val_matches" json:"query_val_matches"`
	PathPartMatches       map[string]StringRegexMap `bson:"path_part_matches" json:"path_part_matches"`
	SessionMetaMatches    map[string]StringRegexMap `bson:"session_meta_matches" json:"session_meta_matches"`
	RequestContextMatches map[string]StringRegexMap `bson:"request_context_matches" json:"request_context_matches"`
	PayloadMatches        StringRegexMap            `bson:"payload_matches" json:"payload_matches"`
}

type RoutingTrigger struct {
	On        RoutingTriggerOnType  `bson:"on" json:"on"`
	Options   RoutingTriggerOptions `bson:"options" json:"options"`
	RewriteTo string                `bson:"rewrite_to" json:"rewrite_to"`
}

type URLRewriteMeta struct {
	Path         string           `bson:"path" json:"path"`
	Method       string           `bson:"method" json:"method"`
	MatchPattern string           `bson:"match_pattern" json:"match_pattern"`
	RewriteTo    string           `bson:"rewrite_to" json:"rewrite_to"`
	Triggers     []RoutingTrigger `bson:"triggers" json:"triggers"`
	MatchRegexp  *regexp.Regexp   `json:"-"`
}

type VirtualMeta struct {
	Disabled             bool       `bson:"disabled" json:"disabled"`
	ResponseFunctionName string     `bson:"response_function_name" json:"response_function_name"`
	FunctionSourceType   SourceMode `bson:"function_source_type" json:"function_source_type"`
	FunctionSourceURI    string     `bson:"function_source_uri" json:"function_source_uri"`
	Path                 string     `bson:"path" json:"path"`
	Method               string     `bson:"method" json:"method"`
	UseSession           bool       `bson:"use_session" json:"use_session"`
	ProxyOnError         bool       `bson:"proxy_on_error" json:"proxy_on_error"`
}

type MethodTransformMeta struct {
	Disabled bool   `bson:"disabled" json:"disabled"`
	Path     string `bson:"path" json:"path"`
	Method   string `bson:"method" json:"method"`
	ToMethod string `bson:"to_method" json:"to_method"`
}

type ValidatePathMeta struct {
	Disabled    bool                    `bson:"disabled" json:"disabled"`
	Path        string                  `bson:"path" json:"path"`
	Method      string                  `bson:"method" json:"method"`
	Schema      map[string]interface{}  `bson:"-" json:"schema"`
	SchemaB64   string                  `bson:"schema_b64" json:"schema_b64,omitempty"`
	SchemaCache gojsonschema.JSONLoader `bson:"-" json:"-"`
	// Allows override of default 422 Unprocessible Entity response code for validation errors.
	ErrorResponseCode int `bson:"error_response_code" json:"error_response_code"`
}

type ValidateRequestMeta struct {
	Enabled bool   `bson:"enabled" json:"enabled"`
	Path    string `bson:"path" json:"path"`
	Method  string `bson:"method" json:"method"`
	// Allows override of default 422 Unprocessible Entity response code for validation errors.
	ErrorResponseCode int `bson:"error_response_code" json:"error_response_code"`
}

type PersistGraphQLMeta struct {
	Path      string                 `bson:"path" json:"path"`
	Method    string                 `bson:"method" json:"method"`
	Operation string                 `bson:"operation" json:"operation"`
	Variables map[string]interface{} `bson:"variables" json:"variables"`
}

type GoPluginMeta struct {
	Disabled   bool   `bson:"disabled" json:"disabled"`
	Path       string `bson:"path" json:"path"`
	Method     string `bson:"method" json:"method"`
	PluginPath string `bson:"plugin_path" json:"plugin_path"`
	SymbolName string `bson:"func_name" json:"func_name"`
}

type ExtendedPathsSet struct {
	Ignored                 []EndPointMeta        `bson:"ignored" json:"ignored,omitempty"`
	WhiteList               []EndPointMeta        `bson:"white_list" json:"white_list,omitempty"`
	BlackList               []EndPointMeta        `bson:"black_list" json:"black_list,omitempty"`
	MockResponse            []MockResponseMeta    `bson:"mock_response" json:"mock_response,omitempty"`
	Cached                  []string              `bson:"cache" json:"cache,omitempty"`
	AdvanceCacheConfig      []CacheMeta           `bson:"advance_cache_config" json:"advance_cache_config,omitempty"`
	Transform               []TemplateMeta        `bson:"transform" json:"transform,omitempty"`
	TransformResponse       []TemplateMeta        `bson:"transform_response" json:"transform_response,omitempty"`
	TransformJQ             []TransformJQMeta     `bson:"transform_jq" json:"transform_jq,omitempty"`
	TransformJQResponse     []TransformJQMeta     `bson:"transform_jq_response" json:"transform_jq_response,omitempty"`
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
	ValidateJSON            []ValidatePathMeta    `bson:"validate_json" json:"validate_json,omitempty"`
	ValidateRequest         []ValidateRequestMeta `bson:"validate_request" json:"validate_request,omitempty"`
	Internal                []InternalMeta        `bson:"internal" json:"internal,omitempty"`
	GoPlugin                []GoPluginMeta        `bson:"go_plugin" json:"go_plugin,omitempty"`
	PersistGraphQL          []PersistGraphQLMeta  `bson:"persist_graphql" json:"persist_graphql"`
}

type VersionDefinition struct {
	Enabled             bool              `bson:"enabled" json:"enabled"`
	Name                string            `bson:"name" json:"name"`
	Default             string            `bson:"default" json:"default"`
	Location            string            `bson:"location" json:"location"`
	Key                 string            `bson:"key" json:"key"`
	StripPath           bool              `bson:"strip_path" json:"strip_path"` // Deprecated. Use StripVersioningData instead.
	StripVersioningData bool              `bson:"strip_versioning_data" json:"strip_versioning_data"`
	Versions            map[string]string `bson:"versions" json:"versions"`
	BaseID              string            `bson:"base_id" json:"-"` // json tag is `-` because we want this to be hidden to user
}

type VersionData struct {
	NotVersioned   bool                   `bson:"not_versioned" json:"not_versioned"`
	DefaultVersion string                 `bson:"default_version" json:"default_version"`
	Versions       map[string]VersionInfo `bson:"versions" json:"versions"`
}

type VersionInfo struct {
	Name      string    `bson:"name" json:"name"`
	Expires   string    `bson:"expires" json:"expires"`
	ExpiresTs time.Time `bson:"-" json:"-"`
	Paths     struct {
		Ignored   []string `bson:"ignored" json:"ignored"`
		WhiteList []string `bson:"white_list" json:"white_list"`
		BlackList []string `bson:"black_list" json:"black_list"`
	} `bson:"paths" json:"paths"`
	UseExtendedPaths            bool              `bson:"use_extended_paths" json:"use_extended_paths"`
	ExtendedPaths               ExtendedPathsSet  `bson:"extended_paths" json:"extended_paths"`
	GlobalHeaders               map[string]string `bson:"global_headers" json:"global_headers"`
	GlobalHeadersRemove         []string          `bson:"global_headers_remove" json:"global_headers_remove"`
	GlobalResponseHeaders       map[string]string `bson:"global_response_headers" json:"global_response_headers"`
	GlobalResponseHeadersRemove []string          `bson:"global_response_headers_remove" json:"global_response_headers_remove"`
	IgnoreEndpointCase          bool              `bson:"ignore_endpoint_case" json:"ignore_endpoint_case"`
	GlobalSizeLimit             int64             `bson:"global_size_limit" json:"global_size_limit"`
	OverrideTarget              string            `bson:"override_target" json:"override_target"`
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
	Disabled       bool   `bson:"disabled" json:"disabled"`
	Name           string `bson:"name" json:"name"`
	Path           string `bson:"path" json:"path"`
	RequireSession bool   `bson:"require_session" json:"require_session"`
	RawBodyOnly    bool   `bson:"raw_body_only" json:"raw_body_only"`
}

// IDExtractorConfig specifies the configuration for ID extractor
type IDExtractorConfig struct {
	// HeaderName is the header name to extract ID from.
	HeaderName string `mapstructure:"header_name" bson:"header_name" json:"header_name"`
	// FormParamName is the form parameter name to extract ID from.
	FormParamName string `mapstructure:"param_name" bson:"param_name" json:"param_name"`
	// RegexExpression is the regular expression to match ID.
	RegexExpression string `mapstructure:"regex_expression" bson:"regex_expression" json:"regex_expression"`
	// RegexMatchIndex is the index from which ID to be extracted after a match.
	RegexMatchIndex int `mapstructure:"regex_match_index" bson:"regex_match_index" json:"regex_match_index"`
	// XPathExp is the xpath expression to match ID.
	XPathExpression string `mapstructure:"xpath_expression" bson:"xpath_expression" json:"xpath_expression"`
}

type MiddlewareIdExtractor struct {
	Disabled        bool                   `bson:"disabled" json:"disabled"`
	ExtractFrom     IdExtractorSource      `bson:"extract_from" json:"extract_from"`
	ExtractWith     IdExtractorType        `bson:"extract_with" json:"extract_with"`
	ExtractorConfig map[string]interface{} `bson:"extractor_config" json:"extractor_config"`
	Extractor       IDExtractor            `bson:"-" json:"-"`
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
	CacheTimeout               int64    `bson:"cache_timeout" json:"cache_timeout"`
	EnableCache                bool     `bson:"enable_cache" json:"enable_cache"`
	CacheAllSafeRequests       bool     `bson:"cache_all_safe_requests" json:"cache_all_safe_requests"`
	CacheOnlyResponseCodes     []int    `bson:"cache_response_codes" json:"cache_response_codes"`
	EnableUpstreamCacheControl bool     `bson:"enable_upstream_cache_control" json:"enable_upstream_cache_control"`
	CacheControlTTLHeader      string   `bson:"cache_control_ttl_header" json:"cache_control_ttl_header"`
	CacheByHeaders             []string `bson:"cache_by_headers" json:"cache_by_headers"`
}

type ResponseProcessor struct {
	Name    string      `bson:"name" json:"name"`
	Options interface{} `bson:"options" json:"options"`
}

type HostCheckObject struct {
	CheckURL            string            `bson:"url" json:"url"`
	Protocol            string            `bson:"protocol" json:"protocol"`
	Timeout             time.Duration     `bson:"timeout" json:"timeout"`
	EnableProxyProtocol bool              `bson:"enable_proxy_protocol" json:"enable_proxy_protocol"`
	Commands            []CheckCommand    `bson:"commands" json:"commands"`
	Method              string            `bson:"method" json:"method"`
	Headers             map[string]string `bson:"headers" json:"headers"`
	Body                string            `bson:"body" json:"body"`
}

type CheckCommand struct {
	Name    string `bson:"name" json:"name"`
	Message string `bson:"message" json:"message"`
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
	CacheDisabled       bool   `bson:"cache_disabled" json:"cache_disabled"`
	CacheTimeout        int64  `bson:"cache_timeout" json:"cache_timeout"`
	EndpointReturnsList bool   `bson:"endpoint_returns_list" json:"endpoint_returns_list"`
}

// CacheOptions returns the timeout value in effect, and a bool if cache is enabled.
func (sd *ServiceDiscoveryConfiguration) CacheOptions() (int64, bool) {
	return sd.CacheTimeout, !sd.CacheDisabled
}

type OIDProviderConfig struct {
	Issuer    string            `bson:"issuer" json:"issuer"`
	ClientIDs map[string]string `bson:"client_ids" json:"client_ids"`
}

type OpenIDOptions struct {
	Providers         []OIDProviderConfig `bson:"providers" json:"providers"`
	SegregateByClient bool                `bson:"segregate_by_client" json:"segregate_by_client"`
}

type ScopeClaim struct {
	ScopeClaimName string            `bson:"scope_claim_name" json:"scope_claim_name,omitempty"`
	ScopeToPolicy  map[string]string `json:"scope_to_policy,omitempty"`
}

type Scopes struct {
	JWT  ScopeClaim `bson:"jwt" json:"jwt,omitempty"`
	OIDC ScopeClaim `bson:"oidc" json:"oidc,omitempty"`
}

// APIDefinition represents the configuration for a single proxied API and it's versions.
//
// swagger:model
type APIDefinition struct {
	Id                  model.ObjectID `bson:"_id,omitempty" json:"id,omitempty" gorm:"primaryKey;column:_id"`
	Name                string         `bson:"name" json:"name"`
	Expiration          string         `bson:"expiration" json:"expiration,omitempty"`
	ExpirationTs        time.Time      `bson:"-" json:"-"`
	Slug                string         `bson:"slug" json:"slug"`
	ListenPort          int            `bson:"listen_port" json:"listen_port"`
	Protocol            string         `bson:"protocol" json:"protocol"`
	EnableProxyProtocol bool           `bson:"enable_proxy_protocol" json:"enable_proxy_protocol"`
	APIID               string         `bson:"api_id" json:"api_id"`
	OrgID               string         `bson:"org_id" json:"org_id"`
	UseKeylessAccess    bool           `bson:"use_keyless" json:"use_keyless"`
	UseOauth2           bool           `bson:"use_oauth2" json:"use_oauth2"`
	ExternalOAuth       ExternalOAuth  `bson:"external_oauth" json:"external_oauth"`
	UseOpenID           bool           `bson:"use_openid" json:"use_openid"`
	OpenIDOptions       OpenIDOptions  `bson:"openid_options" json:"openid_options"`
	Oauth2Meta          struct {
		AllowedAccessTypes     []osin.AccessRequestType    `bson:"allowed_access_types" json:"allowed_access_types"`
		AllowedAuthorizeTypes  []osin.AuthorizeRequestType `bson:"allowed_authorize_types" json:"allowed_authorize_types"`
		AuthorizeLoginRedirect string                      `bson:"auth_login_redirect" json:"auth_login_redirect"`
	} `bson:"oauth_meta" json:"oauth_meta"`
	Auth         AuthConfig            `bson:"auth" json:"auth"` // Deprecated: Use AuthConfigs instead.
	AuthConfigs  map[string]AuthConfig `bson:"auth_configs" json:"auth_configs"`
	UseBasicAuth bool                  `bson:"use_basic_auth" json:"use_basic_auth"`
	BasicAuth    struct {
		DisableCaching     bool   `bson:"disable_caching" json:"disable_caching"`
		CacheTTL           int    `bson:"cache_ttl" json:"cache_ttl"`
		ExtractFromBody    bool   `bson:"extract_from_body" json:"extract_from_body"`
		BodyUserRegexp     string `bson:"body_user_regexp" json:"body_user_regexp"`
		BodyPasswordRegexp string `bson:"body_password_regexp" json:"body_password_regexp"`
	} `bson:"basic_auth" json:"basic_auth"`
	UseMutualTLSAuth   bool     `bson:"use_mutual_tls_auth" json:"use_mutual_tls_auth"`
	ClientCertificates []string `bson:"client_certificates" json:"client_certificates"`

	// UpstreamCertificates stores the domain to certificate mapping for upstream mutualTLS
	UpstreamCertificates map[string]string `bson:"upstream_certificates" json:"upstream_certificates"`
	// UpstreamCertificatesDisabled disables upstream mutualTLS on the API
	UpstreamCertificatesDisabled bool `bson:"upstream_certificates_disabled" json:"upstream_certificates_disabled,omitempty"`

	// PinnedPublicKeys stores the public key pinning details
	PinnedPublicKeys map[string]string `bson:"pinned_public_keys" json:"pinned_public_keys"`
	// CertificatePinningDisabled disables public key pinning
	CertificatePinningDisabled bool `bson:"certificate_pinning_disabled" json:"certificate_pinning_disabled,omitempty"`

	EnableJWT                            bool                   `bson:"enable_jwt" json:"enable_jwt"`
	UseStandardAuth                      bool                   `bson:"use_standard_auth" json:"use_standard_auth"`
	UseGoPluginAuth                      bool                   `bson:"use_go_plugin_auth" json:"use_go_plugin_auth"`       // Deprecated. Use CustomPluginAuthEnabled instead.
	EnableCoProcessAuth                  bool                   `bson:"enable_coprocess_auth" json:"enable_coprocess_auth"` // Deprecated. Use CustomPluginAuthEnabled instead.
	CustomPluginAuthEnabled              bool                   `bson:"custom_plugin_auth_enabled" json:"custom_plugin_auth_enabled"`
	JWTSigningMethod                     string                 `bson:"jwt_signing_method" json:"jwt_signing_method"`
	JWTSource                            string                 `bson:"jwt_source" json:"jwt_source"`
	JWTIdentityBaseField                 string                 `bson:"jwt_identit_base_field" json:"jwt_identity_base_field"`
	JWTClientIDBaseField                 string                 `bson:"jwt_client_base_field" json:"jwt_client_base_field"`
	JWTPolicyFieldName                   string                 `bson:"jwt_policy_field_name" json:"jwt_policy_field_name"`
	JWTDefaultPolicies                   []string               `bson:"jwt_default_policies" json:"jwt_default_policies"`
	JWTIssuedAtValidationSkew            uint64                 `bson:"jwt_issued_at_validation_skew" json:"jwt_issued_at_validation_skew"`
	JWTExpiresAtValidationSkew           uint64                 `bson:"jwt_expires_at_validation_skew" json:"jwt_expires_at_validation_skew"`
	JWTNotBeforeValidationSkew           uint64                 `bson:"jwt_not_before_validation_skew" json:"jwt_not_before_validation_skew"`
	JWTSkipKid                           bool                   `bson:"jwt_skip_kid" json:"jwt_skip_kid"`
	Scopes                               Scopes                 `bson:"scopes" json:"scopes,omitempty"`
	JWTScopeToPolicyMapping              map[string]string      `bson:"jwt_scope_to_policy_mapping" json:"jwt_scope_to_policy_mapping"` // Deprecated: use Scopes.JWT.ScopeToPolicy or Scopes.OIDC.ScopeToPolicy
	JWTScopeClaimName                    string                 `bson:"jwt_scope_claim_name" json:"jwt_scope_claim_name"`               // Deprecated: use Scopes.JWT.ScopeClaimName or Scopes.OIDC.ScopeClaimName
	NotificationsDetails                 NotificationsManager   `bson:"notifications" json:"notifications"`
	EnableSignatureChecking              bool                   `bson:"enable_signature_checking" json:"enable_signature_checking"`
	HmacAllowedClockSkew                 float64                `bson:"hmac_allowed_clock_skew" json:"hmac_allowed_clock_skew"`
	HmacAllowedAlgorithms                []string               `bson:"hmac_allowed_algorithms" json:"hmac_allowed_algorithms"`
	RequestSigning                       RequestSigningMeta     `bson:"request_signing" json:"request_signing"`
	BaseIdentityProvidedBy               AuthTypeEnum           `bson:"base_identity_provided_by" json:"base_identity_provided_by"`
	VersionDefinition                    VersionDefinition      `bson:"definition" json:"definition"`
	VersionData                          VersionData            `bson:"version_data" json:"version_data"` // Deprecated. Use VersionDefinition instead.
	UptimeTests                          UptimeTests            `bson:"uptime_tests" json:"uptime_tests"`
	Proxy                                ProxyConfig            `bson:"proxy" json:"proxy"`
	DisableRateLimit                     bool                   `bson:"disable_rate_limit" json:"disable_rate_limit"`
	DisableQuota                         bool                   `bson:"disable_quota" json:"disable_quota"`
	CustomMiddleware                     MiddlewareSection      `bson:"custom_middleware" json:"custom_middleware"`
	CustomMiddlewareBundle               string                 `bson:"custom_middleware_bundle" json:"custom_middleware_bundle"`
	CustomMiddlewareBundleDisabled       bool                   `bson:"custom_middleware_bundle_disabled" json:"custom_middleware_bundle_disabled"`
	CacheOptions                         CacheOptions           `bson:"cache_options" json:"cache_options"`
	SessionLifetimeRespectsKeyExpiration bool                   `bson:"session_lifetime_respects_key_expiration" json:"session_lifetime_respects_key_expiration,omitempty"`
	SessionLifetime                      int64                  `bson:"session_lifetime" json:"session_lifetime"`
	Active                               bool                   `bson:"active" json:"active"`
	Internal                             bool                   `bson:"internal" json:"internal"`
	AuthProvider                         AuthProviderMeta       `bson:"auth_provider" json:"auth_provider"`
	SessionProvider                      SessionProviderMeta    `bson:"session_provider" json:"session_provider"`
	EventHandlers                        EventHandlerMetaConfig `bson:"event_handlers" json:"event_handlers"`
	EnableBatchRequestSupport            bool                   `bson:"enable_batch_request_support" json:"enable_batch_request_support"`
	EnableIpWhiteListing                 bool                   `mapstructure:"enable_ip_whitelisting" bson:"enable_ip_whitelisting" json:"enable_ip_whitelisting"`
	AllowedIPs                           []string               `mapstructure:"allowed_ips" bson:"allowed_ips" json:"allowed_ips"`
	EnableIpBlacklisting                 bool                   `mapstructure:"enable_ip_blacklisting" bson:"enable_ip_blacklisting" json:"enable_ip_blacklisting"`
	BlacklistedIPs                       []string               `mapstructure:"blacklisted_ips" bson:"blacklisted_ips" json:"blacklisted_ips"`
	DontSetQuotasOnCreate                bool                   `mapstructure:"dont_set_quota_on_create" bson:"dont_set_quota_on_create" json:"dont_set_quota_on_create"`
	ExpireAnalyticsAfter                 int64                  `mapstructure:"expire_analytics_after" bson:"expire_analytics_after" json:"expire_analytics_after"` // must have an expireAt TTL index set (http://docs.mongodb.org/manual/tutorial/expire-data/)
	ResponseProcessors                   []ResponseProcessor    `bson:"response_processors" json:"response_processors"`
	CORS                                 CORSConfig             `bson:"CORS" json:"CORS"`
	Domain                               string                 `bson:"domain" json:"domain"`
	DomainDisabled                       bool                   `bson:"domain_disabled" json:"domain_disabled,omitempty"`
	Certificates                         []string               `bson:"certificates" json:"certificates"`
	DoNotTrack                           bool                   `bson:"do_not_track" json:"do_not_track"`
	EnableContextVars                    bool                   `bson:"enable_context_vars" json:"enable_context_vars"`
	ConfigData                           map[string]interface{} `bson:"config_data" json:"config_data"`
	ConfigDataDisabled                   bool                   `bson:"config_data_disabled" json:"config_data_disabled"`
	TagHeaders                           []string               `bson:"tag_headers" json:"tag_headers"`
	GlobalRateLimit                      GlobalRateLimit        `bson:"global_rate_limit" json:"global_rate_limit"`
	StripAuthData                        bool                   `bson:"strip_auth_data" json:"strip_auth_data"`
	EnableDetailedRecording              bool                   `bson:"enable_detailed_recording" json:"enable_detailed_recording"`
	GraphQL                              GraphQLConfig          `bson:"graphql" json:"graphql"`
	AnalyticsPlugin                      AnalyticsPluginConfig  `bson:"analytics_plugin" json:"analytics_plugin,omitempty"`

	// Gateway segment tags
	TagsDisabled bool     `bson:"tags_disabled" json:"tags_disabled,omitempty"`
	Tags         []string `bson:"tags" json:"tags"`

	// IsOAS is set to true when API has an OAS definition (created in OAS or migrated to OAS)
	IsOAS       bool   `bson:"is_oas" json:"is_oas,omitempty"`
	VersionName string `bson:"-" json:"-"`

	LastUpdated int `bson:"last_updated" json:"last_updated"`
}

type AnalyticsPluginConfig struct {
	Enabled    bool   `bson:"enable" json:"enable,omitempty"`
	PluginPath string `bson:"plugin_path" json:"plugin_path,omitempty"`
	FuncName   string `bson:"func_name" json:"func_name,omitempty"`
}

type UptimeTests struct {
	CheckList []HostCheckObject `bson:"check_list" json:"check_list"`
	Config    UptimeTestsConfig `bson:"config" json:"config"`
}

type UptimeTestsConfig struct {
	ExpireUptimeAnalyticsAfter int64                         `bson:"expire_utime_after" json:"expire_utime_after"` // must have an expireAt TTL index set (http://docs.mongodb.org/manual/tutorial/expire-data/)
	ServiceDiscovery           ServiceDiscoveryConfiguration `bson:"service_discovery" json:"service_discovery"`
	RecheckWait                int                           `bson:"recheck_wait" json:"recheck_wait"`
}

type AuthConfig struct {
	Name              string          `mapstructure:"name" bson:"name" json:"name"`
	UseParam          bool            `mapstructure:"use_param" bson:"use_param" json:"use_param"`
	ParamName         string          `mapstructure:"param_name" bson:"param_name" json:"param_name"`
	UseCookie         bool            `mapstructure:"use_cookie" bson:"use_cookie" json:"use_cookie"`
	CookieName        string          `mapstructure:"cookie_name" bson:"cookie_name" json:"cookie_name"`
	DisableHeader     bool            `mapstructure:"disable_header" bson:"disable_header" json:"disable_header"`
	AuthHeaderName    string          `mapstructure:"auth_header_name" bson:"auth_header_name" json:"auth_header_name"`
	UseCertificate    bool            `mapstructure:"use_certificate" bson:"use_certificate" json:"use_certificate"`
	ValidateSignature bool            `mapstructure:"validate_signature" bson:"validate_signature" json:"validate_signature"`
	Signature         SignatureConfig `mapstructure:"signature" bson:"signature" json:"signature,omitempty"`
}

type SignatureConfig struct {
	Algorithm        string `mapstructure:"algorithm" bson:"algorithm" json:"algorithm"`
	Header           string `mapstructure:"header" bson:"header" json:"header"`
	UseParam         bool   `mapstructure:"use_param" bson:"use_param" json:"use_param"`
	ParamName        string `mapstructure:"param_name" bson:"param_name" json:"param_name"`
	Secret           string `mapstructure:"secret" bson:"secret" json:"secret"`
	AllowedClockSkew int64  `mapstructure:"allowed_clock_skew" bson:"allowed_clock_skew" json:"allowed_clock_skew"`
	ErrorCode        int    `mapstructure:"error_code" bson:"error_code" json:"error_code"`
	ErrorMessage     string `mapstructure:"error_message" bson:"error_message" json:"error_message"`
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

type RequestSigningMeta struct {
	IsEnabled       bool     `bson:"is_enabled" json:"is_enabled"`
	Secret          string   `bson:"secret" json:"secret"`
	KeyId           string   `bson:"key_id" json:"key_id"`
	Algorithm       string   `bson:"algorithm" json:"algorithm"`
	HeaderList      []string `bson:"header_list" json:"header_list"`
	CertificateId   string   `bson:"certificate_id" json:"certificate_id"`
	SignatureHeader string   `bson:"signature_header" json:"signature_header"`
}

type ProxyConfig struct {
	PreserveHostHeader          bool                          `bson:"preserve_host_header" json:"preserve_host_header"`
	ListenPath                  string                        `bson:"listen_path" json:"listen_path"`
	TargetURL                   string                        `bson:"target_url" json:"target_url"`
	DisableStripSlash           bool                          `bson:"disable_strip_slash" json:"disable_strip_slash"`
	StripListenPath             bool                          `bson:"strip_listen_path" json:"strip_listen_path"`
	EnableLoadBalancing         bool                          `bson:"enable_load_balancing" json:"enable_load_balancing"`
	Targets                     []string                      `bson:"target_list" json:"target_list"`
	StructuredTargetList        *HostList                     `bson:"-" json:"-"`
	CheckHostAgainstUptimeTests bool                          `bson:"check_host_against_uptime_tests" json:"check_host_against_uptime_tests"`
	ServiceDiscovery            ServiceDiscoveryConfiguration `bson:"service_discovery" json:"service_discovery"`
	Transport                   struct {
		SSLInsecureSkipVerify   bool     `bson:"ssl_insecure_skip_verify" json:"ssl_insecure_skip_verify"`
		SSLCipherSuites         []string `bson:"ssl_ciphers" json:"ssl_ciphers"`
		SSLMinVersion           uint16   `bson:"ssl_min_version" json:"ssl_min_version"`
		SSLMaxVersion           uint16   `bson:"ssl_max_version" json:"ssl_max_version"`
		SSLForceCommonNameCheck bool     `json:"ssl_force_common_name_check"`
		ProxyURL                string   `bson:"proxy_url" json:"proxy_url"`
	} `bson:"transport" json:"transport"`
}

type CORSConfig struct {
	Enable             bool     `bson:"enable" json:"enable"`
	AllowedOrigins     []string `bson:"allowed_origins" json:"allowed_origins"`
	AllowedMethods     []string `bson:"allowed_methods" json:"allowed_methods"`
	AllowedHeaders     []string `bson:"allowed_headers" json:"allowed_headers"`
	ExposedHeaders     []string `bson:"exposed_headers" json:"exposed_headers"`
	AllowCredentials   bool     `bson:"allow_credentials" json:"allow_credentials"`
	MaxAge             int      `bson:"max_age" json:"max_age"`
	OptionsPassthrough bool     `bson:"options_passthrough" json:"options_passthrough"`
	Debug              bool     `bson:"debug" json:"debug"`
}

// GraphQLConfig is the root config object for a GraphQL API.
type GraphQLConfig struct {
	// Enabled indicates if GraphQL should be enabled.
	Enabled bool `bson:"enabled" json:"enabled"`
	// ExecutionMode is the mode to define how an api behaves.
	ExecutionMode GraphQLExecutionMode `bson:"execution_mode" json:"execution_mode"`
	// Version defines the version of the GraphQL config and engine to be used.
	Version GraphQLConfigVersion `bson:"version" json:"version"`
	// Schema is the GraphQL Schema exposed by the GraphQL API/Upstream/Engine.
	Schema string `bson:"schema" json:"schema"`
	// LastSchemaUpdate contains the date and time of the last triggered schema update to the upstream.
	LastSchemaUpdate *time.Time `bson:"last_schema_update" json:"last_schema_update,omitempty"`
	// TypeFieldConfigurations is a rule set of data source and mapping of a schema field.
	TypeFieldConfigurations []datasource.TypeFieldConfiguration `bson:"type_field_configurations" json:"type_field_configurations"`
	// GraphQLPlayground is the Playground specific configuration.
	GraphQLPlayground GraphQLPlayground `bson:"playground" json:"playground"`
	// Engine holds the configuration for engine v2 and upwards.
	Engine GraphQLEngineConfig `bson:"engine" json:"engine"`
	// Proxy holds the configuration for a proxy only api.
	Proxy GraphQLProxyConfig `bson:"proxy" json:"proxy"`
	// Subgraph holds the configuration for a GraphQL federation subgraph.
	Subgraph GraphQLSubgraphConfig `bson:"subgraph" json:"subgraph"`
	// Supergraph holds the configuration for a GraphQL federation supergraph.
	Supergraph GraphQLSupergraphConfig `bson:"supergraph" json:"supergraph"`
}

type GraphQLConfigVersion string

const (
	GraphQLConfigVersionNone GraphQLConfigVersion = ""
	GraphQLConfigVersion1    GraphQLConfigVersion = "1"
	GraphQLConfigVersion2    GraphQLConfigVersion = "2"
)

type GraphQLProxyConfig struct {
	AuthHeaders      map[string]string `bson:"auth_headers" json:"auth_headers"`
	SubscriptionType SubscriptionType  `bson:"subscription_type" json:"subscription_type,omitempty"`
	RequestHeaders   map[string]string `bson:"request_headers" json:"request_headers"`
}

type GraphQLSubgraphConfig struct {
	SDL string `bson:"sdl" json:"sdl"`
}

type GraphQLSupergraphConfig struct {
	// UpdatedAt contains the date and time of the last update of a supergraph API.
	UpdatedAt            *time.Time              `bson:"updated_at" json:"updated_at,omitempty"`
	Subgraphs            []GraphQLSubgraphEntity `bson:"subgraphs" json:"subgraphs"`
	MergedSDL            string                  `bson:"merged_sdl" json:"merged_sdl"`
	GlobalHeaders        map[string]string       `bson:"global_headers" json:"global_headers"`
	DisableQueryBatching bool                    `bson:"disable_query_batching" json:"disable_query_batching"`
}

type GraphQLSubgraphEntity struct {
	APIID            string            `bson:"api_id" json:"api_id"`
	Name             string            `bson:"name" json:"name"`
	URL              string            `bson:"url" json:"url"`
	SDL              string            `bson:"sdl" json:"sdl"`
	Headers          map[string]string `bson:"headers" json:"headers"`
	SubscriptionType SubscriptionType  `bson:"subscription_type" json:"subscription_type,omitempty"`
}

type GraphQLEngineConfig struct {
	FieldConfigs []GraphQLFieldConfig      `bson:"field_configs" json:"field_configs"`
	DataSources  []GraphQLEngineDataSource `bson:"data_sources" json:"data_sources"`
}

type GraphQLFieldConfig struct {
	TypeName              string   `bson:"type_name" json:"type_name"`
	FieldName             string   `bson:"field_name" json:"field_name"`
	DisableDefaultMapping bool     `bson:"disable_default_mapping" json:"disable_default_mapping"`
	Path                  []string `bson:"path" json:"path"`
}

type GraphQLEngineDataSourceKind string

const (
	GraphQLEngineDataSourceKindREST    = "REST"
	GraphQLEngineDataSourceKindGraphQL = "GraphQL"
	GraphQLEngineDataSourceKindKafka   = "Kafka"
)

type GraphQLEngineDataSource struct {
	Kind       GraphQLEngineDataSourceKind `bson:"kind" json:"kind"`
	Name       string                      `bson:"name" json:"name"`
	Internal   bool                        `bson:"internal" json:"internal"`
	RootFields []GraphQLTypeFields         `bson:"root_fields" json:"root_fields"`
	Config     json.RawMessage             `bson:"config" json:"config"`
}

type GraphQLTypeFields struct {
	Type   string   `bson:"type" json:"type"`
	Fields []string `bson:"fields" json:"fields"`
}

type GraphQLEngineDataSourceConfigREST struct {
	URL     string            `bson:"url" json:"url"`
	Method  string            `bson:"method" json:"method"`
	Headers map[string]string `bson:"headers" json:"headers"`
	Query   []QueryVariable   `bson:"query" json:"query"`
	Body    string            `bson:"body" json:"body"`
}

type GraphQLEngineDataSourceConfigGraphQL struct {
	URL              string            `bson:"url" json:"url"`
	Method           string            `bson:"method" json:"method"`
	Headers          map[string]string `bson:"headers" json:"headers"`
	SubscriptionType SubscriptionType  `bson:"subscription_type" json:"subscription_type,omitempty"`
	HasOperation     bool              `bson:"has_operation" json:"has_operation"`
	Operation        string            `bson:"operation" json:"operation"`
	Variables        json.RawMessage   `bson:"variables" json:"variables"`
}

type GraphQLEngineDataSourceConfigKafka struct {
	BrokerAddresses      []string              `bson:"broker_addresses" json:"broker_addresses"`
	Topics               []string              `bson:"topics" json:"topics"`
	GroupID              string                `bson:"group_id" json:"group_id"`
	ClientID             string                `bson:"client_id" json:"client_id"`
	KafkaVersion         string                `bson:"kafka_version" json:"kafka_version"`
	StartConsumingLatest bool                  `json:"start_consuming_latest"`
	BalanceStrategy      string                `json:"balance_strategy"`
	IsolationLevel       string                `json:"isolation_level"`
	SASL                 kafka_datasource.SASL `json:"sasl"`
}

type QueryVariable struct {
	Name  string `bson:"name" json:"name"`
	Value string `bson:"value" json:"value"`
}

// GraphQLExecutionMode is the mode in which the GraphQL Middleware should operate.
type GraphQLExecutionMode string

const (
	// GraphQLExecutionModeProxyOnly is the mode in which the GraphQL Middleware doesn't evaluate the GraphQL request
	// In other terms, the GraphQL Middleware will not act as a GraphQL server in itself.
	// The GraphQL Middleware will (optionally) validate the request and leave the execution up to the upstream.
	GraphQLExecutionModeProxyOnly GraphQLExecutionMode = "proxyOnly"
	// GraphQLExecutionModeExecutionEngine is the mode in which the GraphQL Middleware will evaluate every request.
	// This means the Middleware will act as a independent GraphQL service which might delegate partial execution to upstreams.
	GraphQLExecutionModeExecutionEngine GraphQLExecutionMode = "executionEngine"
	// GraphQLExecutionModeSubgraph is the mode if the API is defined as a subgraph for usage in GraphQL federation.
	// It will basically act the same as an API in proxyOnly mode but can be used in a supergraph.
	GraphQLExecutionModeSubgraph GraphQLExecutionMode = "subgraph"
	// GraphQLExecutionModeSupergraph is the mode where an API is able to use subgraphs to build a supergraph in GraphQL federation.
	GraphQLExecutionModeSupergraph GraphQLExecutionMode = "supergraph"
)

// GraphQLPlayground represents the configuration for the public playground which will be hosted alongside the api.
type GraphQLPlayground struct {
	// Enabled indicates if the playground should be enabled.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Path sets the path on which the playground will be hosted if enabled.
	Path string `bson:"path" json:"path"`
}

// EncodeForDB will encode map[string]struct variables for saving in URL format
func (a *APIDefinition) EncodeForDB() {
	newVersion := make(map[string]VersionInfo)
	for k, v := range a.VersionData.Versions {
		newK := base64.StdEncoding.EncodeToString([]byte(k))
		v.Name = newK
		newVersion[newK] = v
	}
	a.VersionData.Versions = newVersion

	newUpstreamCerts := make(map[string]string)
	for domain, cert := range a.UpstreamCertificates {
		newD := base64.StdEncoding.EncodeToString([]byte(domain))
		newUpstreamCerts[newD] = cert
	}
	a.UpstreamCertificates = newUpstreamCerts

	newPinnedPublicKeys := make(map[string]string)
	for domain, cert := range a.PinnedPublicKeys {
		newD := base64.StdEncoding.EncodeToString([]byte(domain))
		newPinnedPublicKeys[newD] = cert
	}
	a.PinnedPublicKeys = newPinnedPublicKeys

	for i, version := range a.VersionData.Versions {
		for j, oldSchema := range version.ExtendedPaths.ValidateJSON {

			jsBytes, _ := json.Marshal(oldSchema.Schema)
			oldSchema.SchemaB64 = base64.StdEncoding.EncodeToString(jsBytes)

			a.VersionData.Versions[i].ExtendedPaths.ValidateJSON[j] = oldSchema
		}
	}

	// Auth is deprecated so this code tries to maintain backward compatibility
	if a.Auth.AuthHeaderName == "" {
		a.Auth = a.AuthConfigs["authToken"]
	}
}

func (a *APIDefinition) DecodeFromDB() {
	newVersion := make(map[string]VersionInfo)
	for k, v := range a.VersionData.Versions {
		newK, err := base64.StdEncoding.DecodeString(k)
		if err != nil {
			log.Error("Couldn't Decode, leaving as it may be legacy...")
			newVersion[k] = v
		} else {
			v.Name = string(newK)
			newVersion[string(newK)] = v
		}
	}
	a.VersionData.Versions = newVersion

	newUpstreamCerts := make(map[string]string)
	for domain, cert := range a.UpstreamCertificates {
		newD, err := base64.StdEncoding.DecodeString(domain)
		if err != nil {
			log.Error("Couldn't Decode, leaving as it may be legacy...")
			newUpstreamCerts[domain] = cert
		} else {
			newUpstreamCerts[string(newD)] = cert
		}
	}
	a.UpstreamCertificates = newUpstreamCerts

	newPinnedPublicKeys := make(map[string]string)
	for domain, cert := range a.PinnedPublicKeys {
		newD, err := base64.StdEncoding.DecodeString(domain)
		if err != nil {
			log.Error("Couldn't Decode, leaving as it may be legacy...")
			newPinnedPublicKeys[domain] = cert
		} else {
			newPinnedPublicKeys[string(newD)] = cert
		}
	}
	a.PinnedPublicKeys = newPinnedPublicKeys

	for i, version := range a.VersionData.Versions {
		for j, oldSchema := range version.ExtendedPaths.ValidateJSON {
			jsBytes, _ := base64.StdEncoding.DecodeString(oldSchema.SchemaB64)

			json.Unmarshal(jsBytes, &oldSchema.Schema)
			oldSchema.SchemaB64 = ""

			a.VersionData.Versions[i].ExtendedPaths.ValidateJSON[j] = oldSchema
		}
	}

	// Auth is deprecated so this code tries to maintain backward compatibility
	makeCompatible := func(authType string, enabled bool) {
		if a.AuthConfigs == nil {
			a.AuthConfigs = make(map[string]AuthConfig)
		}

		_, ok := a.AuthConfigs[authType]

		if !ok && enabled {
			a.AuthConfigs[authType] = a.Auth
		}
	}

	makeCompatible("authToken", a.UseStandardAuth)
	makeCompatible("jwt", a.EnableJWT)
}

// Expired returns true if this Version has expired
// and false if it has not expired (or does not have any expiry)
func (v *VersionInfo) Expired() bool {
	// Never expires
	if v.Expires == "" || v.Expires == "-1" {
		return false
	}

	// otherwise use parsed timestamp
	if v.ExpiresTs.IsZero() {
		log.Error("Could not parse expiry date, disallow")
		return true
	}

	return time.Since(v.ExpiresTs) >= 0
}

// ExpiryTime returns the time that this version is due to expire
func (v *VersionInfo) ExpiryTime() (exp time.Time) {
	if v.Expired() {
		return exp
	}
	exp = v.ExpiresTs
	return
}

func (s *StringRegexMap) Check(value string) (match string) {
	if s.matchRegex == nil {
		return
	}

	return s.matchRegex.FindString(value)
}

func (s *StringRegexMap) FindStringSubmatch(value string) (matched bool, match []string) {
	if s.matchRegex == nil {
		return
	}

	match = s.matchRegex.FindStringSubmatch(value)
	if !s.Reverse {
		matched = len(match) > 0
	} else {
		matched = len(match) == 0
	}

	return
}

func (s *StringRegexMap) FindAllStringSubmatch(value string, n int) (matched bool, matches [][]string) {
	matches = s.matchRegex.FindAllStringSubmatch(value, n)
	if !s.Reverse {
		matched = len(matches) > 0
	} else {
		matched = len(matches) == 0
	}

	return
}

func (s *StringRegexMap) Init() error {
	var err error
	if s.matchRegex, err = regexp.Compile(s.MatchPattern); err != nil {
		log.WithError(err).WithField("MatchPattern", s.MatchPattern).
			Error("Could not compile matchRegex for StringRegexMap")
		return err
	}

	return nil
}

func (a *APIDefinition) GenerateAPIID() {
	a.APIID = uuid.NewHex()
}

func (a *APIDefinition) GetAPIDomain() string {
	if a.DomainDisabled {
		return ""
	}
	return a.Domain
}

func DummyAPI() APIDefinition {
	endpointMeta := EndPointMeta{
		Path: "abc",
		MethodActions: map[string]EndpointMethodMeta{
			"GET": {
				Action:  Reply,
				Code:    200,
				Data:    "testdata",
				Headers: map[string]string{"header": "value"},
			},
		},
	}
	templateMeta := TemplateMeta{
		TemplateData: TemplateData{Input: RequestJSON, Mode: UseBlob},
	}
	transformJQMeta := TransformJQMeta{
		Filter: "filter",
		Path:   "path",
		Method: "method",
	}
	headerInjectionMeta := HeaderInjectionMeta{
		DeleteHeaders: []string{"header1", "header2"},
		AddHeaders:    map[string]string{},
		Path:          "path",
		Method:        "method",
	}
	hardTimeoutMeta := HardTimeoutMeta{Path: "path", Method: "method", TimeOut: 0}
	circuitBreakerMeta := CircuitBreakerMeta{
		Path:                 "path",
		Method:               "method",
		ThresholdPercent:     0.0,
		Samples:              0,
		ReturnToServiceAfter: 0,
	}
	// TODO: Extend triggers
	urlRewriteMeta := URLRewriteMeta{
		Path:         "",
		Method:       "method",
		MatchPattern: "matchpattern",
		RewriteTo:    "rewriteto",
		Triggers:     []RoutingTrigger{},
	}
	virtualMeta := VirtualMeta{
		ResponseFunctionName: "responsefunctioname",
		FunctionSourceType:   "functionsourcetype",
		FunctionSourceURI:    "functionsourceuri",
		Path:                 "path",
		Method:               "method",
	}
	sizeLimit := RequestSizeMeta{
		Path:      "path",
		Method:    "method",
		SizeLimit: 0,
	}
	methodTransformMeta := MethodTransformMeta{Path: "path", Method: "method", ToMethod: "tomethod"}
	trackEndpointMeta := TrackEndpointMeta{Path: "path", Method: "method"}
	internalMeta := InternalMeta{Path: "path", Method: "method"}
	validatePathMeta := ValidatePathMeta{Path: "path", Method: "method", Schema: map[string]interface{}{}, SchemaB64: ""}
	paths := struct {
		Ignored   []string `bson:"ignored" json:"ignored"`
		WhiteList []string `bson:"white_list" json:"white_list"`
		BlackList []string `bson:"black_list" json:"black_list"`
	}{
		Ignored:   []string{},
		WhiteList: []string{},
		BlackList: []string{},
	}
	versionInfo := VersionInfo{
		Name:             "Default",
		UseExtendedPaths: true,
		Paths:            paths,
		ExtendedPaths: ExtendedPathsSet{
			Ignored:                 []EndPointMeta{endpointMeta},
			WhiteList:               []EndPointMeta{endpointMeta},
			BlackList:               []EndPointMeta{endpointMeta},
			Cached:                  []string{},
			Transform:               []TemplateMeta{templateMeta},
			TransformResponse:       []TemplateMeta{templateMeta},
			TransformJQ:             []TransformJQMeta{transformJQMeta},
			TransformJQResponse:     []TransformJQMeta{transformJQMeta},
			TransformHeader:         []HeaderInjectionMeta{headerInjectionMeta},
			TransformResponseHeader: []HeaderInjectionMeta{headerInjectionMeta},
			HardTimeouts:            []HardTimeoutMeta{hardTimeoutMeta},
			CircuitBreaker:          []CircuitBreakerMeta{circuitBreakerMeta},
			URLRewrite:              []URLRewriteMeta{urlRewriteMeta},
			Virtual:                 []VirtualMeta{virtualMeta},
			SizeLimit:               []RequestSizeMeta{sizeLimit},
			MethodTransforms:        []MethodTransformMeta{methodTransformMeta},
			TrackEndpoints:          []TrackEndpointMeta{trackEndpointMeta},
			DoNotTrackEndpoints:     []TrackEndpointMeta{trackEndpointMeta},
			Internal:                []InternalMeta{internalMeta},
			ValidateJSON:            []ValidatePathMeta{validatePathMeta},
		},
	}
	versionData := struct {
		NotVersioned   bool                   `bson:"not_versioned" json:"not_versioned"`
		DefaultVersion string                 `bson:"default_version" json:"default_version"`
		Versions       map[string]VersionInfo `bson:"versions" json:"versions"`
	}{
		NotVersioned:   true,
		DefaultVersion: "",
		Versions: map[string]VersionInfo{
			"Default": versionInfo,
		},
	}

	defaultCORSConfig := CORSConfig{
		Enable:         false,
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{http.MethodGet, http.MethodPost, http.MethodHead},
		AllowedHeaders: []string{"Origin", "Accept", "Content-Type", "X-Requested-With", "Authorization"},
	}

	graphql := GraphQLConfig{
		Enabled:          false,
		ExecutionMode:    GraphQLExecutionModeProxyOnly,
		Version:          GraphQLConfigVersion2,
		LastSchemaUpdate: nil,
		Proxy: GraphQLProxyConfig{
			AuthHeaders: map[string]string{},
		},
	}

	return APIDefinition{
		VersionData:          versionData,
		ConfigData:           map[string]interface{}{},
		AllowedIPs:           []string{},
		PinnedPublicKeys:     map[string]string{},
		ResponseProcessors:   []ResponseProcessor{},
		ClientCertificates:   []string{},
		BlacklistedIPs:       []string{},
		TagHeaders:           []string{},
		UpstreamCertificates: map[string]string{},
		Scopes: Scopes{
			JWT: ScopeClaim{
				ScopeToPolicy: map[string]string{},
			},
			OIDC: ScopeClaim{
				ScopeToPolicy: map[string]string{},
			},
		},
		HmacAllowedAlgorithms: []string{},
		CustomMiddleware: MiddlewareSection{
			Post:        []MiddlewareDefinition{},
			Pre:         []MiddlewareDefinition{},
			PostKeyAuth: []MiddlewareDefinition{},
			AuthCheck:   MiddlewareDefinition{},
			IdExtractor: MiddlewareIdExtractor{
				ExtractorConfig: map[string]interface{}{},
			},
		},
		Proxy: ProxyConfig{
			DisableStripSlash: true,
		},
		CORS:    defaultCORSConfig,
		Tags:    []string{},
		GraphQL: graphql,
	}
}

func (a *APIDefinition) GetScopeClaimName() string {
	if reflect.IsEmpty(a.Scopes) {
		return a.JWTScopeClaimName
	}

	if a.UseOpenID {
		return a.Scopes.OIDC.ScopeClaimName
	}

	return a.Scopes.JWT.ScopeClaimName
}

func (a *APIDefinition) GetScopeToPolicyMapping() map[string]string {
	if reflect.IsEmpty(a.Scopes) {
		return a.JWTScopeToPolicyMapping
	}

	if a.UseOpenID {
		return a.Scopes.OIDC.ScopeToPolicy
	}

	return a.Scopes.JWT.ScopeToPolicy
}

var Template = template.New("").Funcs(map[string]interface{}{
	"jsonMarshal": func(v interface{}) (string, error) {
		bs, err := json.Marshal(v)
		return string(bs), err
	},
	"xmlMarshal": func(v interface{}) (string, error) {
		var err error
		var xmlValue []byte
		mv, ok := v.(mxj.Map)
		if ok {
			mxj.XMLEscapeChars(true)
			xmlValue, err = mv.Xml()
		} else {
			res, ok := v.(map[string]interface{})
			if ok {
				mxj.XMLEscapeChars(true)
				xmlValue, err = mxj.Map(res).Xml()
			} else {
				xmlValue, err = xml.MarshalIndent(v, "", "  ")
			}
		}

		return string(xmlValue), err
	},
})

type ExternalOAuth struct {
	Enabled   bool       `bson:"enabled" json:"enabled"`
	Providers []Provider `bson:"providers" json:"providers"`
}

type Provider struct {
	JWT           JWTValidation `bson:"jwt" json:"jwt"`
	Introspection Introspection `bson:"introspection" json:"introspection"`
}

type JWTValidation struct {
	Enabled                 bool   `bson:"enabled" json:"enabled"`
	SigningMethod           string `bson:"signing_method" json:"signing_method"`
	Source                  string `bson:"source" json:"source"`
	IssuedAtValidationSkew  uint64 `bson:"issued_at_validation_skew" json:"issued_at_validation_skew"`
	NotBeforeValidationSkew uint64 `bson:"not_before_validation_skew" json:"not_before_validation_skew"`
	ExpiresAtValidationSkew uint64 `bson:"expires_at_validation_skew" json:"expires_at_validation_skew"`
	IdentityBaseField       string `bson:"identity_base_field" json:"identity_base_field"`
}

type Introspection struct {
	Enabled           bool               `bson:"enabled" json:"enabled"`
	URL               string             `bson:"url" json:"url"`
	ClientID          string             `bson:"client_id" json:"client_id"`
	ClientSecret      string             `bson:"client_secret" json:"client_secret"`
	IdentityBaseField string             `bson:"identity_base_field" json:"identity_base_field"`
	Cache             IntrospectionCache `bson:"cache" json:"cache"`
}

type IntrospectionCache struct {
	Enabled bool  `bson:"enabled" json:"enabled"`
	Timeout int64 `bson:"timeout" json:"timeout"`
}

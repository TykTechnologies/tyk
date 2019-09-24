package config

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/kelseyhightower/envconfig"

	"github.com/TykTechnologies/tyk/apidef"
	logger "github.com/TykTechnologies/tyk/log"
	"github.com/TykTechnologies/tyk/regexp"
)

type IPsHandleStrategy string

var (
	log      = logger.Get()
	global   atomic.Value
	globalMu sync.Mutex

	Default = Config{
		ListenPort:     8080,
		Secret:         "352d20ee67be67f6340b4c0605b044b7",
		TemplatePath:   "templates",
		MiddlewarePath: "middleware",
		AppPath:        "apps/",
		Storage: StorageOptionsConf{
			Type:    "redis",
			Host:    "localhost",
			MaxIdle: 100,
			Port:    6379,
		},
		AnalyticsConfig: AnalyticsConfigConfig{
			IgnoredIPs: make([]string, 0),
		},
		DnsCache: DnsCacheConfig{
			Enabled:                   false,
			TTL:                       dnsCacheDefaultTtl,
			CheckInterval:             dnsCacheDefaultCheckInterval,
			MultipleIPsHandleStrategy: NoCacheStrategy,
		},
	}
)

const (
	envPrefix = "TYK_GW"

	dnsCacheDefaultTtl           = 3600
	dnsCacheDefaultCheckInterval = 60

	PickFirstStrategy IPsHandleStrategy = "pick_first"
	RandomStrategy    IPsHandleStrategy = "random"
	NoCacheStrategy   IPsHandleStrategy = "no_cache"

	DefaultDashPolicySource     = "service"
	DefaultDashPolicyRecordName = "tyk_policies"
)

type PoliciesConfig struct {
	PolicySource           string `json:"policy_source"`
	PolicyConnectionString string `json:"policy_connection_string"`
	PolicyRecordName       string `json:"policy_record_name"`
	AllowExplicitPolicyID  bool   `json:"allow_explicit_policy_id"`
}

type DBAppConfOptionsConfig struct {
	ConnectionString string   `json:"connection_string"`
	NodeIsSegmented  bool     `json:"node_is_segmented"`
	Tags             []string `json:"tags"`
}

type StorageOptionsConf struct {
	Type                  string            `json:"type"`
	Host                  string            `json:"host"`
	Port                  int               `json:"port"`
	Hosts                 map[string]string `json:"hosts"`
	Username              string            `json:"username"`
	Password              string            `json:"password"`
	Database              int               `json:"database"`
	MaxIdle               int               `json:"optimisation_max_idle"`
	MaxActive             int               `json:"optimisation_max_active"`
	Timeout               int               `json:"timeout"`
	EnableCluster         bool              `json:"enable_cluster"`
	UseSSL                bool              `json:"use_ssl"`
	SSLInsecureSkipVerify bool              `json:"ssl_insecure_skip_verify"`
}

type NormalisedURLConfig struct {
	Enabled            bool                 `json:"enabled"`
	NormaliseUUIDs     bool                 `json:"normalise_uuids"`
	NormaliseNumbers   bool                 `json:"normalise_numbers"`
	Custom             []string             `json:"custom_patterns"`
	CompiledPatternSet NormaliseURLPatterns `json:"-"` // see analytics.go
}

type NormaliseURLPatterns struct {
	UUIDs  *regexp.Regexp
	IDs    *regexp.Regexp
	Custom []*regexp.Regexp
}

type AnalyticsConfigConfig struct {
	Type                    string              `json:"type"`
	IgnoredIPs              []string            `json:"ignored_ips"`
	EnableDetailedRecording bool                `json:"enable_detailed_recording"`
	EnableGeoIP             bool                `json:"enable_geo_ip"`
	GeoIPDBLocation         string              `json:"geo_ip_db_path"`
	NormaliseUrls           NormalisedURLConfig `json:"normalise_urls"`
	PoolSize                int                 `json:"pool_size"`
	RecordsBufferSize       uint64              `json:"records_buffer_size"`
	StorageExpirationTime   int                 `json:"storage_expiration_time"`
	ignoredIPsCompiled      map[string]bool
}

type HealthCheckConfig struct {
	EnableHealthChecks      bool  `json:"enable_health_checks"`
	HealthCheckValueTimeout int64 `json:"health_check_value_timeouts"`
}

type DnsCacheConfig struct {
	Enabled                   bool              `json:"enabled"`
	TTL                       int64             `json:"ttl"`
	CheckInterval             int64             `json:"-" ignored:"true"` //controls cache cleanup interval. By convention shouldn't be exposed to config or env_variable_setup
	MultipleIPsHandleStrategy IPsHandleStrategy `json:"multiple_ips_handle_strategy"`
}

type MonitorConfig struct {
	EnableTriggerMonitors bool               `json:"enable_trigger_monitors"`
	Config                WebHookHandlerConf `json:"configuration"`
	GlobalTriggerLimit    float64            `json:"global_trigger_limit"`
	MonitorUserKeys       bool               `json:"monitor_user_keys"`
	MonitorOrgKeys        bool               `json:"monitor_org_keys"`
}

type WebHookHandlerConf struct {
	Method       string            `bson:"method" json:"method"`
	TargetPath   string            `bson:"target_path" json:"target_path"`
	TemplatePath string            `bson:"template_path" json:"template_path"`
	HeaderList   map[string]string `bson:"header_map" json:"header_map"`
	EventTimeout int64             `bson:"event_timeout" json:"event_timeout"`
}

type SlaveOptionsConfig struct {
	UseRPC                          bool   `json:"use_rpc"`
	UseSSL                          bool   `json:"use_ssl"`
	SSLInsecureSkipVerify           bool   `json:"ssl_insecure_skip_verify"`
	ConnectionString                string `json:"connection_string"`
	RPCKey                          string `json:"rpc_key"`
	APIKey                          string `json:"api_key"`
	EnableRPCCache                  bool   `json:"enable_rpc_cache"`
	BindToSlugsInsteadOfListenPaths bool   `json:"bind_to_slugs"`
	DisableKeySpaceSync             bool   `json:"disable_keyspace_sync"`
	GroupID                         string `json:"group_id"`
	CallTimeout                     int    `json:"call_timeout"`
	PingTimeout                     int    `json:"ping_timeout"`
	RPCPoolSize                     int    `json:"rpc_pool_size"`
}

type LocalSessionCacheConf struct {
	DisableCacheSessionState bool `json:"disable_cached_session_state"`
	CachedSessionTimeout     int  `json:"cached_session_timeout"`
	CacheSessionEviction     int  `json:"cached_session_eviction"`
}

type HttpServerOptionsConfig struct {
	OverrideDefaults       bool       `json:"override_defaults"`
	ReadTimeout            int        `json:"read_timeout"`
	WriteTimeout           int        `json:"write_timeout"`
	UseSSL                 bool       `json:"use_ssl"`
	UseLE_SSL              bool       `json:"use_ssl_le"`
	EnableHttp2            bool       `json:"enable_http2"`
	SSLInsecureSkipVerify  bool       `json:"ssl_insecure_skip_verify"`
	EnableWebSockets       bool       `json:"enable_websockets"`
	Certificates           []CertData `json:"certificates"`
	SSLCertificates        []string   `json:"ssl_certificates"`
	ServerName             string     `json:"server_name"`
	MinVersion             uint16     `json:"min_version"`
	FlushInterval          int        `json:"flush_interval"`
	SkipURLCleaning        bool       `json:"skip_url_cleaning"`
	SkipTargetPathEscaping bool       `json:"skip_target_path_escaping"`
	Ciphers                []string   `json:"ssl_ciphers"`
}

type AuthOverrideConf struct {
	ForceAuthProvider    bool                       `json:"force_auth_provider"`
	AuthProvider         apidef.AuthProviderMeta    `json:"auth_provider"`
	ForceSessionProvider bool                       `json:"force_session_provider"`
	SessionProvider      apidef.SessionProviderMeta `json:"session_provider"`
}

type UptimeTestsConfigDetail struct {
	FailureTriggerSampleSize int  `json:"failure_trigger_sample_size"`
	TimeWait                 int  `json:"time_wait"`
	CheckerPoolSize          int  `json:"checker_pool_size"`
	EnableUptimeAnalytics    bool `json:"enable_uptime_analytics"`
}

type UptimeTestsConfig struct {
	Disable bool                    `json:"disable"`
	Config  UptimeTestsConfigDetail `json:"config"`
}

type ServiceDiscoveryConf struct {
	DefaultCacheTimeout int `json:"default_cache_timeout"`
}

type CoProcessConfig struct {
	EnableCoProcess     bool   `json:"enable_coprocess"`
	CoProcessGRPCServer string `json:"coprocess_grpc_server"`
	PythonPathPrefix    string `json:"python_path_prefix"`
	PythonVersion       string `json:"python_version"`
}

type CertificatesConfig struct {
	API        []string          `json:"apis"`
	Upstream   map[string]string `json:"upstream"`
	ControlAPI []string          `json:"control_api"`
	Dashboard  []string          `json:"dashboard_api"`
	MDCB       []string          `json:"mdcb_api"`
}

type SecurityConfig struct {
	PrivateCertificateEncodingSecret string             `json:"private_certificate_encoding_secret"`
	ControlAPIUseMutualTLS           bool               `json:"control_api_use_mutual_tls"`
	PinnedPublicKeys                 map[string]string  `json:"pinned_public_keys"`
	Certificates                     CertificatesConfig `json:"certificates"`
}

type NewRelicConfig struct {
	AppName    string `json:"app_name"`
	LicenseKey string `json:"license_key"`
}

type Tracer struct {
	// The name of the tracer to initialize. For instance appdash, to use appdash
	// tracer
	Name string `json:"name"`

	// If true then this tracer will be activated and all tracing data will be sent
	// to this tracer.NoOp tracer is used otherwise which collects traces but
	// discard them.
	Enabled bool `json:"enabled"`

	// Key value pairs used to initialize the tracer. These are tracer specific,
	// each tracer requires different options to operate. Please see trace package
	// for options required by supported tracer implementation.
	Options map[string]interface{} `json:"options"`
}

// ServicePort defines a protocol and port on which a service can bind to
type ServicePort struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

// PortWhiteList defines ports that will be allowed by the gateway.
type PortWhiteList struct {
	Ranges []PortRange `json:"ranges,omitempty"`
	Ports  []int       `json:"ports,omitempty"`
}

// Match returns true if port is acceptable from the PortWhiteList.
func (p PortWhiteList) Match(port int) bool {
	for _, v := range p.Ports {
		if port == v {
			return true
		}
	}
	for _, r := range p.Ranges {
		if r.Match(port) {
			return true
		}
	}
	return false
}

// PortRange defines a range of ports inclusively.
type PortRange struct {
	From int `json:"from"`
	To   int `json:"to"`
}

// Match returns true if port is within the range
func (r PortRange) Match(port int) bool {
	return r.From <= port && r.To >= port
}

// Config is the configuration object used by tyk to set up various parameters.
type Config struct {
	// OriginalPath is the path to the config file that was read. If
	// none was found, it's the path to the default config file that
	// was written.
	OriginalPath string `json:"-"`

	HostName                  string                  `json:"hostname"`
	ListenAddress             string                  `json:"listen_address"`
	ListenPort                int                     `json:"listen_port"`
	ControlAPIHostname        string                  `json:"control_api_hostname"`
	ControlAPIPort            int                     `json:"control_api_port"`
	Secret                    string                  `json:"secret"`
	NodeSecret                string                  `json:"node_secret"`
	PIDFileLocation           string                  `json:"pid_file_location"`
	AllowInsecureConfigs      bool                    `json:"allow_insecure_configs"`
	PublicKeyPath             string                  `json:"public_key_path"`
	AllowRemoteConfig         bool                    `bson:"allow_remote_config" json:"allow_remote_config"`
	Security                  SecurityConfig          `json:"security"`
	HttpServerOptions         HttpServerOptionsConfig `json:"http_server_options"`
	ReloadWaitTime            int                     `bson:"reload_wait_time" json:"reload_wait_time"`
	VersionHeader             string                  `json:"version_header"`
	UseAsyncSessionWrite      bool                    `json:"optimisations_use_async_session_write"`
	SuppressRedisSignalReload bool                    `json:"suppress_redis_signal_reload"`

	// Gateway Security Policies
	HashKeys                bool           `json:"hash_keys"`
	HashKeyFunction         string         `json:"hash_key_function"`
	EnableHashedKeysListing bool           `json:"enable_hashed_keys_listing"`
	MinTokenLength          int            `json:"min_token_length"`
	EnableAPISegregation    bool           `json:"enable_api_segregation"`
	TemplatePath            string         `json:"template_path"`
	Policies                PoliciesConfig `json:"policies"`
	DisablePortWhiteList    bool           `json:"disable_ports_whitelist"`
	// Defines the ports that will be available for the api services to bind to.
	// This is a map of protocol to PortWhiteList. This allows per protocol
	// configurations.
	PortWhiteList map[string]PortWhiteList `json:"ports_whitelist"`

	// CE Configurations
	AppPath string `json:"app_path"`

	// Dashboard Configurations
	UseDBAppConfigs          bool                   `json:"use_db_app_configs"`
	DBAppConfOptions         DBAppConfOptionsConfig `json:"db_app_conf_options"`
	Storage                  StorageOptionsConf     `json:"storage"`
	DisableDashboardZeroConf bool                   `json:"disable_dashboard_zeroconf"`

	// Slave Configurations
	SlaveOptions   SlaveOptionsConfig `json:"slave_options"`
	ManagementNode bool               `json:"management_node"`
	AuthOverride   AuthOverrideConf   `json:"auth_override"`

	// Rate Limiting Strategy
	EnableNonTransactionalRateLimiter bool `json:"enable_non_transactional_rate_limiter"`
	EnableSentinelRateLimiter         bool `json:"enable_sentinel_rate_limiter"`
	EnableRedisRollingLimiter         bool `json:"enable_redis_rolling_limiter"`
	DRLNotificationFrequency          int  `json:"drl_notification_frequency"`

	// Organization configurations
	EnforceOrgDataAge               bool          `json:"enforce_org_data_age"`
	EnforceOrgDataDetailLogging     bool          `json:"enforce_org_data_detail_logging"`
	EnforceOrgQuotas                bool          `json:"enforce_org_quotas"`
	ExperimentalProcessOrgOffThread bool          `json:"experimental_process_org_off_thread"`
	Monitor                         MonitorConfig `json:"monitor"`

	// Client-Gateway Configuration
	MaxIdleConns         int   `bson:"max_idle_connections" json:"max_idle_connections"`
	MaxIdleConnsPerHost  int   `bson:"max_idle_connections_per_host" json:"max_idle_connections_per_host"`
	MaxConnTime          int64 `json:"max_conn_time"`
	CloseIdleConnections bool  `json:"close_idle_connections"`
	CloseConnections     bool  `json:"close_connections"`
	EnableCustomDomains  bool  `json:"enable_custom_domains"`
	// If AllowMasterKeys is set to true, session objects (key definitions) that do not have explicit access rights set
	// will be allowed by Tyk. This means that keys that are created have access to ALL APIs, which in many cases is
	// unwanted behaviour unless you are sure about what you are doing.
	AllowMasterKeys bool `json:"allow_master_keys"`

	// Gateway-Service Configuration
	ServiceDiscovery              ServiceDiscoveryConf `json:"service_discovery"`
	ProxySSLInsecureSkipVerify    bool                 `json:"proxy_ssl_insecure_skip_verify"`
	ProxyEnableHttp2              bool                 `json:"proxy_enable_http2"`
	ProxySSLMinVersion            uint16               `json:"proxy_ssl_min_version"`
	ProxySSLCipherSuites          []string             `json:"proxy_ssl_ciphers"`
	ProxyDefaultTimeout           float64              `json:"proxy_default_timeout"`
	ProxySSLDisableRenegotiation  bool                 `json:"proxy_ssl_disable_renegotiation"`
	ProxyCloseConnections         bool                 `json:"proxy_close_connections"`
	UptimeTests                   UptimeTestsConfig    `json:"uptime_tests"`
	HealthCheck                   HealthCheckConfig    `json:"health_check"`
	OauthRefreshExpire            int64                `json:"oauth_refresh_token_expire"`
	OauthTokenExpire              int32                `json:"oauth_token_expire"`
	OauthTokenExpiredRetainPeriod int32                `json:"oauth_token_expired_retain_period"`
	OauthRedirectUriSeparator     string               `json:"oauth_redirect_uri_separator"`
	EnableKeyLogging              bool                 `json:"enable_key_logging"`

	// Proxy analytics configuration
	EnableAnalytics bool                  `json:"enable_analytics"`
	AnalyticsConfig AnalyticsConfigConfig `json:"analytics_config"`

	// Cache
	DnsCache                 DnsCacheConfig        `json:"dns_cache"`
	DisableRegexpCache       bool                  `json:"disable_regexp_cache"`
	RegexpCacheExpire        int32                 `json:"regexp_cache_expire"`
	LocalSessionCache        LocalSessionCacheConf `json:"local_session_cache"`
	EnableSeperateCacheStore bool                  `json:"enable_separate_cache_store"`
	CacheStorage             StorageOptionsConf    `json:"cache_storage"`

	// Middleware/Plugin Configuration
	EnableBundleDownloader  bool            `bson:"enable_bundle_downloader" json:"enable_bundle_downloader"`
	BundleBaseURL           string          `bson:"bundle_base_url" json:"bundle_base_url"`
	EnableJSVM              bool            `json:"enable_jsvm"`
	JSVMTimeout             int             `json:"jsvm_timeout"`
	DisableVirtualPathBlobs bool            `json:"disable_virtual_path_blobs"`
	TykJSPath               string          `json:"tyk_js_path"`
	MiddlewarePath          string          `json:"middleware_path"`
	CoProcessOptions        CoProcessConfig `json:"coprocess_options"`

	// Monitoring, Logging & Profiling
	LogLevel                string         `json:"log_level"`
	HealthCheckEndpointName string         `json:"health_check_endpoint_name"`
	Tracer                  Tracer         `json:"tracing"`
	NewRelic                NewRelicConfig `json:"newrelic"`
	HTTPProfile             bool           `json:"enable_http_profiler"`
	UseRedisLog             bool           `json:"use_redis_log"`
	SentryCode              string         `json:"sentry_code"`
	UseSentry               bool           `json:"use_sentry"`
	UseSyslog               bool           `json:"use_syslog"`
	UseGraylog              bool           `json:"use_graylog"`
	UseLogstash             bool           `json:"use_logstash"`
	GraylogNetworkAddr      string         `json:"graylog_network_addr"`
	LogstashNetworkAddr     string         `json:"logstash_network_addr"`
	SyslogTransport         string         `json:"syslog_transport"`
	LogstashTransport       string         `json:"logstash_transport"`
	SyslogNetworkAddr       string         `json:"syslog_network_addr"`
	StatsdConnectionString  string         `json:"statsd_connection_string"`
	StatsdPrefix            string         `json:"statsd_prefix"`

	// Event System
	EventHandlers        apidef.EventHandlerMetaConfig         `json:"event_handlers"`
	EventTriggers        map[apidef.TykEvent][]TykEventHandler `json:"event_trigers_defunct"`  // Deprecated: Config.GetEventTriggers instead.
	EventTriggersDefunct map[apidef.TykEvent][]TykEventHandler `json:"event_triggers_defunct"` // Deprecated: Config.GetEventTriggers instead.

	// TODO: These config options are not documented - What do they do?
	SessionUpdatePoolSize          int   `json:"session_update_pool_size"`
	SessionUpdateBufferSize        int   `json:"session_update_buffer_size"`
	SupressDefaultOrgStore         bool  `json:"suppress_default_org_store"`
	LegacyEnableAllowanceCountdown bool  `bson:"legacy_enable_allowance_countdown" json:"legacy_enable_allowance_countdown"`
	GlobalSessionLifetime          int64 `bson:"global_session_lifetime" json:"global_session_lifetime"`
	ForceGlobalSessionLifetime     bool  `bson:"force_global_session_lifetime" json:"force_global_session_lifetime"`
	HideGeneratorHeader            bool  `json:"hide_generator_header"`
}

// GetEventTriggers returns event triggers. There was a typo in the json tag.
// To maintain backward compatibility, this solution is chosen.
func (c Config) GetEventTriggers() map[apidef.TykEvent][]TykEventHandler {
	if c.EventTriggersDefunct == nil {
		return c.EventTriggers
	}

	if c.EventTriggers != nil {
		log.Info("Both event_trigers_defunct and event_triggers_defunct are configured in the config," +
			" event_triggers_defunct will be used.")
	}

	return c.EventTriggersDefunct
}

func (c *Config) SetEventTriggers(eventTriggers map[apidef.TykEvent][]TykEventHandler) {
	c.EventTriggersDefunct = eventTriggers
}

type CertData struct {
	Name     string `json:"domain_name"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

// EventMessage is a standard form to send event data to handlers
type EventMessage struct {
	Type      apidef.TykEvent
	Meta      interface{}
	TimeStamp string
}

// TykEventHandler defines an event handler, e.g. LogMessageEventHandler will handle an event by logging it to stdout.
type TykEventHandler interface {
	Init(interface{}) error
	HandleEvent(EventMessage)
}

func init() {
	SetGlobal(Config{})
}

func Global() Config {
	return global.Load().(Config)
}

func SetGlobal(conf Config) {
	globalMu.Lock()
	defer globalMu.Unlock()
	global.Store(conf)
}

func WriteConf(path string, conf *Config) error {
	bs, err := json.MarshalIndent(conf, "", "    ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, bs, 0644)
}

// writeDefault will set conf to the default config and write it to disk
// in path, if the path is non-empty.
func WriteDefault(path string, conf *Config) error {
	_, b, _, _ := runtime.Caller(0)
	configPath := filepath.Dir(b)
	rootPath := filepath.Dir(configPath)
	Default.TemplatePath = filepath.Join(rootPath, "templates")

	*conf = Default
	if err := envconfig.Process(envPrefix, conf); err != nil {
		return err
	}
	if path == "" {
		return nil
	}
	return WriteConf(path, conf)
}

// Load will load a configuration file, trying each of the paths given
// and using the first one that is a regular file and can be opened.
//
// If none exists, a default config will be written to the first path in
// the list.
//
// An error will be returned only if any of the paths existed but was
// not a valid config file.
func Load(paths []string, conf *Config) error {
	var r io.Reader
	for _, path := range paths {
		f, err := os.Open(path)
		if err == nil {
			r = f
			conf.OriginalPath = path
			break
		}
		if os.IsNotExist(err) {
			continue
		}
		return err
	}
	if r == nil {
		path := paths[0]
		log.Warnf("No config file found, writing default to %s", path)
		if err := WriteDefault(path, conf); err != nil {
			return err
		}
		log.Info("Loading default configuration...")
		return Load([]string{path}, conf)
	}
	if err := json.NewDecoder(r).Decode(&conf); err != nil {
		return fmt.Errorf("couldn't unmarshal config: %v", err)
	}
	if err := envconfig.Process(envPrefix, conf); err != nil {
		return fmt.Errorf("failed to process config env vars: %v", err)
	}
	return nil
}

func (c *Config) LoadIgnoredIPs() {
	c.AnalyticsConfig.ignoredIPsCompiled = make(map[string]bool, len(c.AnalyticsConfig.IgnoredIPs))
	for _, ip := range c.AnalyticsConfig.IgnoredIPs {
		c.AnalyticsConfig.ignoredIPsCompiled[ip] = true
	}
}

func (c *Config) StoreAnalytics(ip string) bool {
	if !c.EnableAnalytics {
		return false
	}

	return !c.AnalyticsConfig.ignoredIPsCompiled[ip]
}

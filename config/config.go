package config

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"

	"github.com/kelseyhightower/envconfig"

	"github.com/TykTechnologies/tyk/apidef"
	logger "github.com/TykTechnologies/tyk/log"
)

var log = logger.Get()

var Global Config

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
	StorageExpirationTime   int                 `json:"storage_expiration_time"`
	ignoredIPsCompiled      map[string]bool
}

type HealthCheckConfig struct {
	EnableHealthChecks      bool  `json:"enable_health_checks"`
	HealthCheckValueTimeout int64 `json:"health_check_value_timeouts"`
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
	Certificates                     CertificatesConfig `json:"certificates"`
}

type NewRelicConfig struct {
	AppName    string `json:"app_name"`
	LicenseKey string `json:"license_key"`
}

// Config is the configuration object used by tyk to set up various parameters.
type Config struct {
	// OriginalPath is the path to the config file that was read. If
	// none was found, it's the path to the default config file that
	// was written.
	OriginalPath string `json:"-"`

	ListenAddress                     string                                `json:"listen_address"`
	ListenPort                        int                                   `json:"listen_port"`
	Secret                            string                                `json:"secret"`
	NodeSecret                        string                                `json:"node_secret"`
	TemplatePath                      string                                `json:"template_path"`
	TykJSPath                         string                                `json:"tyk_js_path"`
	MiddlewarePath                    string                                `json:"middleware_path"`
	Policies                          PoliciesConfig                        `json:"policies"`
	UseDBAppConfigs                   bool                                  `json:"use_db_app_configs"`
	DBAppConfOptions                  DBAppConfOptionsConfig                `json:"db_app_conf_options"`
	DisableDashboardZeroConf          bool                                  `json:"disable_dashboard_zeroconf"`
	AppPath                           string                                `json:"app_path"`
	Storage                           StorageOptionsConf                    `json:"storage"`
	EnableSeperateCacheStore          bool                                  `json:"enable_separate_cache_store"`
	CacheStorage                      StorageOptionsConf                    `json:"cache_storage"`
	EnableAnalytics                   bool                                  `json:"enable_analytics"`
	AnalyticsConfig                   AnalyticsConfigConfig                 `json:"analytics_config"`
	HealthCheck                       HealthCheckConfig                     `json:"health_check"`
	UseAsyncSessionWrite              bool                                  `json:"optimisations_use_async_session_write"`
	AllowMasterKeys                   bool                                  `json:"allow_master_keys"`
	HashKeys                          bool                                  `json:"hash_keys"`
	SuppressRedisSignalReload         bool                                  `json:"suppress_redis_signal_reload"`
	SupressDefaultOrgStore            bool                                  `json:"suppress_default_org_store"`
	UseRedisLog                       bool                                  `json:"use_redis_log"`
	SentryCode                        string                                `json:"sentry_code"`
	UseSentry                         bool                                  `json:"use_sentry"`
	UseSyslog                         bool                                  `json:"use_syslog"`
	UseGraylog                        bool                                  `json:"use_graylog"`
	UseLogstash                       bool                                  `json:"use_logstash"`
	GraylogNetworkAddr                string                                `json:"graylog_network_addr"`
	LogstashNetworkAddr               string                                `json:"logstash_network_addr"`
	SyslogTransport                   string                                `json:"syslog_transport"`
	LogstashTransport                 string                                `json:"logstash_transport"`
	SyslogNetworkAddr                 string                                `json:"syslog_network_addr"`
	StatsdConnectionString            string                                `json:"statsd_connection_string"`
	StatsdPrefix                      string                                `json:"statsd_prefix"`
	EnforceOrgDataAge                 bool                                  `json:"enforce_org_data_age"`
	EnforceOrgDataDetailLogging       bool                                  `json:"enforce_org_data_detail_logging"`
	EnforceOrgQuotas                  bool                                  `json:"enforce_org_quotas"`
	ExperimentalProcessOrgOffThread   bool                                  `json:"experimental_process_org_off_thread"`
	EnableNonTransactionalRateLimiter bool                                  `json:"enable_non_transactional_rate_limiter"`
	EnableSentinelRateLImiter         bool                                  `json:"enable_sentinel_rate_limiter"`
	EnableRedisRollingLimiter         bool                                  `json:"enable_redis_rolling_limiter"`
	ManagementNode                    bool                                  `json:"management_node"`
	Monitor                           MonitorConfig                         `json:"monitor"`
	OauthRefreshExpire                int64                                 `json:"oauth_refresh_token_expire"`
	OauthTokenExpire                  int32                                 `json:"oauth_token_expire"`
	OauthTokenExpiredRetainPeriod     int32                                 `json:"oauth_token_expired_retain_period"`
	OauthRedirectUriSeparator         string                                `json:"oauth_redirect_uri_separator"`
	SlaveOptions                      SlaveOptionsConfig                    `json:"slave_options"`
	DisableVirtualPathBlobs           bool                                  `json:"disable_virtual_path_blobs"`
	LocalSessionCache                 LocalSessionCacheConf                 `json:"local_session_cache"`
	HttpServerOptions                 HttpServerOptionsConfig               `json:"http_server_options"`
	ServiceDiscovery                  ServiceDiscoveryConf                  `json:"service_discovery"`
	CloseConnections                  bool                                  `json:"close_connections"`
	AuthOverride                      AuthOverrideConf                      `json:"auth_override"`
	UptimeTests                       UptimeTestsConfig                     `json:"uptime_tests"`
	HostName                          string                                `json:"hostname"`
	EnableAPISegregation              bool                                  `json:"enable_api_segregation"`
	ControlAPIHostname                string                                `json:"control_api_hostname"`
	ControlAPIPort                    int                                   `json:"control_api_port"`
	EnableCustomDomains               bool                                  `json:"enable_custom_domains"`
	EnableJSVM                        bool                                  `json:"enable_jsvm"`
	JSVMTimeout                       int                                   `json:"jsvm_timeout"`
	CoProcessOptions                  CoProcessConfig                       `json:"coprocess_options"`
	HideGeneratorHeader               bool                                  `json:"hide_generator_header"`
	EventHandlers                     apidef.EventHandlerMetaConfig         `json:"event_handlers"`
	EventTriggers                     map[apidef.TykEvent][]TykEventHandler `json:"event_trigers_defunct"`
	PIDFileLocation                   string                                `json:"pid_file_location"`
	AllowInsecureConfigs              bool                                  `json:"allow_insecure_configs"`
	PublicKeyPath                     string                                `json:"public_key_path"`
	CloseIdleConnections              bool                                  `json:"close_idle_connections"`
	DRLNotificationFrequency          int                                   `json:"drl_notification_frequency"`
	GlobalSessionLifetime             int64                                 `bson:"global_session_lifetime" json:"global_session_lifetime"`
	ForceGlobalSessionLifetime        bool                                  `bson:"force_global_session_lifetime" json:"force_global_session_lifetime"`
	BundleBaseURL                     string                                `bson:"bundle_base_url" json:"bundle_base_url"`
	EnableBundleDownloader            bool                                  `bson:"enable_bundle_downloader" json:"enable_bundle_downloader"`
	AllowRemoteConfig                 bool                                  `bson:"allow_remote_config" json:"allow_remote_config"`
	LegacyEnableAllowanceCountdown    bool                                  `bson:"legacy_enable_allowance_countdown" json:"legacy_enable_allowance_countdown"`
	MaxIdleConnsPerHost               int                                   `bson:"max_idle_connections_per_host" json:"max_idle_connections_per_host"`
	MaxConnTime                       int64                                 `json:"max_conn_time"`
	ReloadWaitTime                    int                                   `bson:"reload_wait_time" json:"reload_wait_time"`
	ProxySSLInsecureSkipVerify        bool                                  `json:"proxy_ssl_insecure_skip_verify"`
	ProxyDefaultTimeout               int                                   `json:"proxy_default_timeout"`
	LogLevel                          string                                `json:"log_level"`
	Security                          SecurityConfig                        `json:"security"`
	EnableKeyLogging                  bool                                  `json:"enable_key_logging"`
	NewRelic                          NewRelicConfig                        `json:"newrelic"`
	VersionHeader                     string                                `json:"version_header"`
	EnableHashedKeysListing           bool                                  `json:"enable_hashed_keys_listing"`
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

const envPrefix = "TYK_GW"
const defaultListenPort = 8080

var Default = Config{
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

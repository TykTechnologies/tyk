package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/satori/go.uuid"

	"github.com/TykTechnologies/tyk/apidef"
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

type EnvMapString map[string]string

func (e *EnvMapString) Decode(value string) error {
	units := strings.Split(value, ",")
	m := make(map[string]string)
	for _, unit := range units {
		kvArr := strings.Split(unit, ":")
		if len(kvArr) > 1 {
			m[kvArr[0]] = kvArr[1]
		}
	}

	*e = m

	return nil
}

type StorageOptionsConf struct {
	Type          string       `json:"type"`
	Host          string       `json:"host"`
	Port          int          `json:"port"`
	Hosts         EnvMapString `json:"hosts"`
	Username      string       `json:"username"`
	Password      string       `json:"password"`
	Database      int          `json:"database"`
	MaxIdle       int          `json:"optimisation_max_idle"`
	MaxActive     int          `json:"optimisation_max_active"`
	EnableCluster bool         `json:"enable_cluster"`
}

type NormalisedURLConfig struct {
	Enabled            bool                 `json:"enabled"`
	NormaliseUUIDs     bool                 `json:"normalise_uuids"`
	NormaliseNumbers   bool                 `json:"normalise_numbers"`
	Custom             []string             `json:"custom_patterns"`
	compiledPatternSet NormaliseURLPatterns // see analytics.go
}

type AnalyticsConfigConfig struct {
	Type                    string              `json:"type"`
	IgnoredIPs              []string            `json:"ignored_ips"`
	EnableDetailedRecording bool                `json:"enable_detailed_recording"`
	EnableGeoIP             bool                `json:"enable_geo_ip"`
	GeoIPDBLocation         string              `json:"geo_ip_db_path"`
	NormaliseUrls           NormalisedURLConfig `json:"normalise_urls"`
	PoolSize                int                 `json:"pool_size"`
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

type SlaveOptionsConfig struct {
	UseRPC                          bool   `json:"use_rpc"`
	ConnectionString                string `json:"connection_string"`
	RPCKey                          string `json:"rpc_key"`
	APIKey                          string `json:"api_key"`
	EnableRPCCache                  bool   `json:"enable_rpc_cache"`
	BindToSlugsInsteadOfListenPaths bool   `json:"bind_to_slugs"`
	DisableKeySpaceSync             bool   `json:"disable_keyspace_sync"`
	GroupID                         string `json:"group_id"`
	CallTimeout                     int    `json:"call_timeout"`
	PingTimeout                     int    `json:"ping_timeout"`
}

type LocalSessionCacheConf struct {
	DisableCacheSessionState bool `json:"disable_cached_session_state"`
	CachedSessionTimeout     int  `json:"cached_session_timeout"`
	CacheSessionEviction     int  `json:"cached_session_eviction"`
}

type HttpServerOptionsConfig struct {
	OverrideDefaults bool       `json:"override_defaults"`
	ReadTimeout      int        `json:"read_timeout"`
	WriteTimeout     int        `json:"write_timeout"`
	UseSSL           bool       `json:"use_ssl"`
	UseLE_SSL        bool       `json:"use_ssl_le"`
	EnableWebSockets bool       `json:"enable_websockets"`
	Certificates     []CertData `json:"certificates"`
	ServerName       string     `json:"server_name"`
	MinVersion       uint16     `json:"min_version"`
	FlushInterval    int        `json:"flush_interval"`
	SkipURLCleaning  bool       `json:"skip_url_cleaning"`
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
}

// Config is the configuration object used by tyk to set up various parameters.
type Config struct {
	ListenAddress                     string                 `json:"listen_address"`
	ListenPort                        int                    `json:"listen_port"`
	Secret                            string                 `json:"secret"`
	NodeSecret                        string                 `json:"node_secret"`
	TemplatePath                      string                 `json:"template_path"`
	TykJSPath                         string                 `json:"tyk_js_path"`
	MiddlewarePath                    string                 `json:"middleware_path"`
	Policies                          PoliciesConfig         `json:"policies"`
	UseDBAppConfigs                   bool                   `json:"use_db_app_configs"`
	DBAppConfOptions                  DBAppConfOptionsConfig `json:"db_app_conf_options"`
	DisableDashboardZeroConf          bool                   `json:"disable_dashboard_zeroconf"`
	AppPath                           string                 `json:"app_path"`
	Storage                           StorageOptionsConf     `json:"storage"`
	EnableSeperateCacheStore          bool                   `json:"enable_separate_cache_store"`
	CacheStorage                      StorageOptionsConf     `json:"cache_storage"`
	EnableAnalytics                   bool                   `json:"enable_analytics"`
	AnalyticsConfig                   AnalyticsConfigConfig  `json:"analytics_config"`
	HealthCheck                       HealthCheckConfig      `json:"health_check"`
	UseAsyncSessionWrite              bool                   `json:"optimisations_use_async_session_write"`
	AllowMasterKeys                   bool                   `json:"allow_master_keys"`
	HashKeys                          bool                   `json:"hash_keys"`
	SuppressRedisSignalReload         bool                   `json:"suppress_redis_signal_reload"`
	SupressDefaultOrgStore            bool                   `json:"suppress_default_org_store"`
	UseRedisLog                       bool                   `json:"use_redis_log"`
	SentryCode                        string                 `json:"sentry_code"`
	UseSentry                         bool                   `json:"use_sentry"`
	UseSyslog                         bool                   `json:"use_syslog"`
	UseGraylog                        bool                   `json:"use_graylog"`
	UseLogstash                       bool                   `json:"use_logstash"`
	GraylogNetworkAddr                string                 `json:"graylog_network_addr"`
	LogstashNetworkAddr               string                 `json:"logstash_network_addr"`
	SyslogTransport                   string                 `json:"syslog_transport"`
	LogstashTransport                 string                 `json:"logstash_transport"`
	SyslogNetworkAddr                 string                 `json:"syslog_network_addr"`
	StatsdConnectionString            string                 `json:"statsd_connection_string"`
	StatsdPrefix                      string                 `json:"statsd_prefix"`
	EnforceOrgDataAge                 bool                   `json:"enforce_org_data_age"`
	EnforceOrgDataDeailLogging        bool                   `json:"enforce_org_data_detail_logging"`
	EnforceOrgQuotas                  bool                   `json:"enforce_org_quotas"`
	ExperimentalProcessOrgOffThread   bool                   `json:"experimental_process_org_off_thread"`
	EnableNonTransactionalRateLimiter bool                   `json:"enable_non_transactional_rate_limiter"`
	EnableSentinelRateLImiter         bool                   `json:"enable_sentinel_rate_limiter"`
	EnableRedisRollingLimiter         bool                   `json:"enable_redis_rolling_limiter"`
	ManagementNode                    bool                   `json:"management_node"`
	Monitor                           MonitorConfig
	OauthRefreshExpire                int64                                 `json:"oauth_refresh_token_expire"`
	OauthTokenExpire                  int32                                 `json:"oauth_token_expire"`
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
	ReloadWaitTime                    int                                   `bson:"reload_wait_time" json:"reload_wait_time"`
	UseDistributedQuotaCounter        bool                                  `bson:"use_distributed_counter" json:"use_distributed_counter"`
	DistributedQuotaFlushIntervalInMS int                                   `bson:"distributed_quota_flush_interval_in_ms" json:"distributed_quota_flush_interval_in_ms"`
	DQSetMaster                       bool                                  `bson:"distributed_quota_set_master" json:"distributed_quota_set_master"`
}

type CertData struct {
	Name     string `json:"domain_name"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

const envPrefix = "TYK_GW"

// writeDefaultConf will create a default configuration file and set the storage type to "memory"
func writeDefaultConf(conf *Config) {
	conf.ListenAddress = ""
	conf.ListenPort = 8080
	conf.Secret = "352d20ee67be67f6340b4c0605b044b7"
	conf.TemplatePath = "templates"
	conf.TykJSPath = "js/tyk.js"
	conf.MiddlewarePath = "middleware"
	conf.Storage.Type = "redis"
	conf.AppPath = "apps/"
	conf.Storage.Host = "localhost"
	conf.Storage.Username = ""
	conf.Storage.Password = ""
	conf.Storage.Database = 0
	conf.Storage.MaxIdle = 100
	conf.Storage.Port = 6379
	conf.EnableAnalytics = false
	conf.HealthCheck.EnableHealthChecks = true
	conf.HealthCheck.HealthCheckValueTimeout = 60
	conf.AnalyticsConfig.IgnoredIPs = make([]string, 0)
	conf.UseAsyncSessionWrite = false
	conf.HideGeneratorHeader = false
	conf.OauthRedirectUriSeparator = ""
	if err := envconfig.Process(envPrefix, conf); err != nil {
		log.Error("Failed to process environment variables: ", err)
	}
	newConfig, err := json.MarshalIndent(conf, "", "    ")
	if err != nil {
		log.Error("Problem marshalling default configuration: ", err)
	} else if !runningTests {
		ioutil.WriteFile("tyk.conf", newConfig, 0644)
	}
}

// LoadConfig will load the configuration file from filePath, if it can't open
// the file for reading, it assumes there is no configuration file and will try to create
// one on the default path (tyk.conf in the local directory)
func loadConfig(filePath string, conf *Config) {
	configuration, err := ioutil.ReadFile(filePath)
	if err != nil {
		if !runningTests {
			log.Error("Couldn't load configuration file: ", err)
			log.Info("Writing a default file to tyk.conf")
			writeDefaultConf(conf)
			log.Info("Loading default configuration...")
			loadConfig("tyk.conf", conf)
		}
	} else {
		if err := json.Unmarshal(configuration, &conf); err != nil {
			log.Error("Couldn't unmarshal configuration: ", err)
		}

		if err := envconfig.Process(envPrefix, conf); err != nil {
			log.Error("Failed to process environment variables after file load: ", err)
		}
	}

	if conf.SlaveOptions.CallTimeout == 0 {
		conf.SlaveOptions.CallTimeout = 30
	}
	if conf.SlaveOptions.PingTimeout == 0 {
		conf.SlaveOptions.PingTimeout = 60
	}
	GlobalRPCPingTimeout = time.Second * time.Duration(conf.SlaveOptions.PingTimeout)
	GlobalRPCCallTimeout = time.Second * time.Duration(conf.SlaveOptions.CallTimeout)
	conf.EventTriggers = InitGenericEventHandlers(conf.EventHandlers)
}

func (c *Config) loadIgnoredIPs() {
	c.AnalyticsConfig.ignoredIPsCompiled = make(map[string]bool, len(c.AnalyticsConfig.IgnoredIPs))
	for _, ip := range c.AnalyticsConfig.IgnoredIPs {
		c.AnalyticsConfig.ignoredIPsCompiled[ip] = true
	}
}

func (c *Config) StoreAnalytics(r *http.Request) bool {
	if !c.EnableAnalytics {
		return false
	}

	ip := GetIPFromRequest(r)
	return !c.AnalyticsConfig.ignoredIPsCompiled[ip]
}

func generateRandomNodeID() string {
	u := uuid.NewV4()
	return "solo-" + u.String()
}

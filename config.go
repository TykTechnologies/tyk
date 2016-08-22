package main

import (
	"encoding/json"
	"github.com/TykTechnologies/tykcommon"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
)

// Config is the configuration object used by tyk to set up various parameters.
type Config struct {
	ListenAddress  string `json:"listen_address"`
	ListenPort     int    `json:"listen_port"`
	Secret         string `json:"secret"`
	NodeSecret     string `json:"node_secret"`
	TemplatePath   string `json:"template_path"`
	TykJSPath      string `json:"tyk_js_path"`
	MiddlewarePath string `json:"middleware_path"`
	Policies       struct {
		PolicySource           string `json:"policy_source"`
		PolicyConnectionString string `json:"policy_connection_string"`
		PolicyRecordName       string `json:"policy_record_name"`
		AllowExplicitPolicyID  bool   `json:"allow_explicit_policy_id"`
	} `json:"policies"`
	UseDBAppConfigs  bool `json:"use_db_app_configs"`
	DBAppConfOptions struct {
		ConnectionString string   `json:"connection_string"`
		NodeIsSegmented  bool     `json:"node_is_segmented"`
		Tags             []string `json:"tags"`
	} `json:"db_app_conf_options"`
	DisableDashboardZeroConf bool   `json:"disable_dashboard_zeroconf"`
	AppPath                  string `json:"app_path"`
	Storage                  struct {
		Type          string            `json:"type"`
		Host          string            `json:"host"`
		Port          int               `json:"port"`
		Hosts         map[string]string `json:"hosts"`
		Username      string            `json:"username"`
		Password      string            `json:"password"`
		Database      int               `json:"database"`
		MaxIdle       int               `json:"optimisation_max_idle"`
		MaxActive     int               `json:"optimisation_max_active"`
		EnableCluster bool              `json:"enable_cluster"`
	} `json:"storage"`
	EnableAnalytics bool `json:"enable_analytics"`
	AnalyticsConfig struct {
		Type                    string   `json:"type"`
		IgnoredIPs              []string `json:"ignored_ips"`
		EnableDetailedRecording bool     `json:"enable_detailed_recording"`
		EnableGeoIP             bool     `json:"enable_geo_ip"`
		GeoIPDBLocation         string   `json:"geo_ip_db_path"`
		NormaliseUrls           struct {
			Enabled            bool                 `json:"enabled"`
			NormaliseUUIDs     bool                 `json:"normalise_uuids"`
			NormaliseNumbers   bool                 `json:"normalise_numbers"`
			Custom             []string             `json:"custom_patterns"`
			compiledPatternSet NormaliseURLPatterns // see analytics.go
		} `json:"normalise_urls"`
		ignoredIPsCompiled map[string]bool
	} `json:"analytics_config"`
	HealthCheck struct {
		EnableHealthChecks      bool  `json:"enable_health_checks"`
		HealthCheckValueTimeout int64 `json:"health_check_value_timeouts"`
	} `json:"health_check"`
	UseAsyncSessionWrite              bool   `json:"optimisations_use_async_session_write"`
	AllowMasterKeys                   bool   `json:"allow_master_keys"`
	HashKeys                          bool   `json:"hash_keys"`
	SuppressRedisSignalReload         bool   `json:"suppress_redis_signal_reload"`
	SupressDefaultOrgStore            bool   `json:"suppress_default_org_store"`
	UseRedisLog                       bool   `json:"use_redis_log"`
	SentryCode                        string `json:"sentry_code"`
	UseSentry                         bool   `json:"use_sentry"`
	UseSyslog                         bool   `json:"use_syslog"`
	UseGraylog                        bool   `json:"use_graylog"`
	UseLogstash                       bool   `json:"use_logstash"`
	GraylogNetworkAddr                string `json:"graylog_network_addr"`
	LogstashNetworkAddr               string `json:"logstash_network_addr"`
	SyslogTransport                   string `json:"syslog_transport"`
	LogstashTransport                 string `json:"logstash_transport"`
	SyslogNetworkAddr                 string `json:"syslog_network_addr"`
	EnforceOrgDataAge                 bool   `json:"enforce_org_data_age"`
	EnforceOrgDataDeailLogging        bool   `json:"enforce_org_data_detail_logging"`
	EnforceOrgQuotas                  bool   `json:"enforce_org_quotas"`
	ExperimentalProcessOrgOffThread   bool   `json:"experimental_process_org_off_thread"`
	EnableNonTransactionalRateLimiter bool   `json:"enable_non_transactional_rate_limiter"`
	EnableSentinelRateLImiter         bool   `json:"enable_sentinel_rate_limiter"`
	Monitor                           struct {
		EnableTriggerMonitors bool               `json:"enable_trigger_monitors"`
		Config                WebHookHandlerConf `json:"configuration"`
		GlobalTriggerLimit    float64            `json:"global_trigger_limit"`
		MonitorUserKeys       bool               `json:"monitor_user_keys"`
		MonitorOrgKeys        bool               `json:"monitor_org_keys"`
	}
	OauthRefreshExpire        int64  `json:"oauth_refresh_token_expire"`
	OauthTokenExpire          int32  `json:"oauth_token_expire"`
	OauthRedirectUriSeparator string `json:"oauth_redirect_uri_separator"`
	SlaveOptions              struct {
		UseRPC                          bool   `json:"use_rpc"`
		ConnectionString                string `json:"connection_string"`
		RPCKey                          string `json:"rpc_key"`
		APIKey                          string `json:"api_key"`
		EnableRPCCache                  bool   `json:"enable_rpc_cache"`
		BindToSlugsInsteadOfListenPaths bool   `json:"bind_to_slugs"`
		DisableKeySpaceSync             bool   `json:"disable_keyspace_sync"`
		GroupID                         string `json:"group_id"`
	} `json:"slave_options"`
	DisableVirtualPathBlobs bool `json:"disable_virtual_path_blobs"`
	LocalSessionCache       struct {
		DisableCacheSessionState bool `json:"disable_cached_session_state"`
		CachedSessionTimeout     int  `json:"cached_session_timeout"`
		CacheSessionEviction     int  `json:"cached_session_eviction"`
	} `json:"local_session_cache"`

	HttpServerOptions struct {
		OverrideDefaults bool       `json:"override_defaults"`
		ReadTimeout      int        `json:"read_timeout"`
		WriteTimeout     int        `json:"write_timeout"`
		UseSSL           bool       `json:"use_ssl"`
		EnableWebSockets bool       `json:"enable_websockets"`
		Certificates     []CertData `json:"certificates"`
		ServerName       string     `json:"server_name"`
		MinVersion       uint16     `json:"min_version"`
		FlushInterval    int        `json:"flush_interval"`
	} `json:"http_server_options"`
	ServiceDiscovery struct {
		DefaultCacheTimeout int `json:"default_cache_timeout"`
	} `json:"service_discovery"`
	CloseConnections bool `json:"close_connections"`
	AuthOverride     struct {
		ForceAuthProvider    bool                          `json:"force_auth_provider"`
		AuthProvider         tykcommon.AuthProviderMeta    `json:"auth_provider"`
		ForceSessionProvider bool                          `json:"force_session_provider"`
		SessionProvider      tykcommon.SessionProviderMeta `json:"session_provider"`
	} `json:"auth_override"`
	UptimeTests struct {
		Disable bool `json:"disable"`
		Config  struct {
			FailureTriggerSampleSize int  `json:"failure_trigger_sample_size"`
			TimeWait                 int  `json:"time_wait"`
			CheckerPoolSize          int  `json:"checker_pool_size"`
			EnableUptimeAnalytics    bool `json:"enable_uptime_analytics"`
		} `json:"config"`
	} `json:"uptime_tests"`
	HostName             string                                   `json:"hostname"`
	EnableAPISegregation bool                                     `json:"enable_api_segregation"`
	ControlAPIHostname   string                                   `json:"control_api_hostname"`
	EnableCustomDomains  bool                                     `json:"enable_custom_domains"`
	EnableJSVM           bool                                     `json:"enable_jsvm"`
	EnableCoProcess      bool                                     `json:"enable_coprocess"`
	HideGeneratorHeader  bool                                     `json:"hide_generator_header"`
	EventHandlers        tykcommon.EventHandlerMetaConfig         `json:"event_handlers"`
	EventTriggers        map[tykcommon.TykEvent][]TykEventHandler `json:"event_trigers_defunct"`
	PIDFileLocation      string                                   `json:"pid_file_location"`
	AllowInsecureConfigs bool                                     `json:"allow_insecure_configs"`
	PublicKeyPath        string                                   `json:"public_key_path"`
}

type CertData struct {
	Name     string `json:"domain_name"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

// WriteDefaultConf will create a default configuration file and set the storage type to "memory"
func WriteDefaultConf(configStruct *Config) {
	configStruct.ListenAddress = ""
	configStruct.ListenPort = 8080
	configStruct.Secret = "352d20ee67be67f6340b4c0605b044b7"
	configStruct.TemplatePath = "./templates"
	configStruct.TykJSPath = "./js/tyk.js"
	configStruct.MiddlewarePath = "./middleware"
	configStruct.Storage.Type = "redis"
	configStruct.AppPath = "./apps/"
	configStruct.Storage.Host = "localhost"
	configStruct.Storage.Username = ""
	configStruct.Storage.Password = ""
	configStruct.Storage.Database = 0
	configStruct.Storage.MaxIdle = 100
	configStruct.Storage.Port = 6379
	configStruct.EnableAnalytics = false
	configStruct.HealthCheck.EnableHealthChecks = true
	configStruct.HealthCheck.HealthCheckValueTimeout = 60
	configStruct.AnalyticsConfig.IgnoredIPs = make([]string, 0)
	configStruct.UseAsyncSessionWrite = false
	configStruct.HideGeneratorHeader = false
	configStruct.OauthRedirectUriSeparator = ""
	newConfig, err := json.MarshalIndent(configStruct, "", "    ")
	if err != nil {
		log.Error("Problem marshalling default configuration!")
		log.Error(err)
	} else {
		ioutil.WriteFile("tyk.conf", newConfig, 0644)
	}
}

// LoadConfig will load the configuration file from filePath, if it can't open
// the file for reading, it assumes there is no configuration file and will try to create
// one on the default path (tyk.conf in the local directory)
func loadConfig(filePath string, configStruct *Config) {
	configuration, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Error("Couldn't load configuration file")
		log.Error(err)
		log.Info("Writing a default file to ./tyk.conf")

		WriteDefaultConf(configStruct)

		log.Info("Loading default configuration...")
		loadConfig("tyk.conf", configStruct)
	} else {
		err := json.Unmarshal(configuration, &configStruct)
		if err != nil {
			log.Error("Couldn't unmarshal configuration")
			log.Error(err)
		}
	}

	configStruct.EventTriggers = InitGenericEventHandlers(configStruct.EventHandlers)
}

func (c *Config) loadIgnoredIPs() {
	c.AnalyticsConfig.ignoredIPsCompiled = make(map[string]bool, len(c.AnalyticsConfig.IgnoredIPs))
	for _, ip := range c.AnalyticsConfig.IgnoredIPs {
		c.AnalyticsConfig.ignoredIPsCompiled[ip] = true
	}
}

func (c *Config) TestShowIPs() {
	log.Warning(c.AnalyticsConfig.ignoredIPsCompiled)
}

func (c Config) StoreAnalytics(r *http.Request) bool {
	if !c.EnableAnalytics {
		return false
	}

	ip, _, _ := net.SplitHostPort(r.RemoteAddr)

	forwarded := r.Header.Get("X-FORWARDED-FOR")
	if forwarded != "" {
		ips := strings.Split(forwarded, ", ")
		ip = ips[0]
	}

	_, ignore := c.AnalyticsConfig.ignoredIPsCompiled[ip]

	return !ignore
}

package config

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"

	"github.com/TykTechnologies/tyk/apidef"
	logger "github.com/TykTechnologies/tyk/log"
	"github.com/TykTechnologies/tyk/regexp"
)

type IPsHandleStrategy string

var (
	log = logger.Get()

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
		HealthCheckEndpointName: "hello",
		CoProcessOptions: CoProcessConfig{
			EnableCoProcess: false,
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
	// Set this value to `file` to look in the file system for a definition file. Set to `service` to use the Dashboard service.
	PolicySource string `json:"policy_source"`

	// This option is required if `policies.policy_source` is set to `service`.
	// Set this to the URL of your Tyk Dashboard installation. The URL needs to be formatted as: http://dashboard_host:port.
	PolicyConnectionString string `json:"policy_connection_string"`

	// This option is required if `policies.policy_source` is set to `file`.
	// Specifies the path of your JSON file containing the available policies.
	PolicyRecordName string `json:"policy_record_name"`

	// In a Pro installation, Tyk will load Policy IDs and use the internal object-ID as the ID of the policy.
	// This is not portable in cases where the data needs to be moved from installation to installation.
	//
	// If you set this value to `true`, then the id parameter in a stored policy (or imported policy using the Dashboard API), will be used instead of the internal ID.
	//
	// This option should only be used when moving an installation to a new database.
	AllowExplicitPolicyID bool `json:"allow_explicit_policy_id"`
	// This option is used for storing a policies  if `policies.policy_source` is set to `file`.
	// it should be some existing file path on hard drive
	PolicyPath string `json:"policy_path"`
}

type DBAppConfOptionsConfig struct {
	// Set the URL to your Dashboard instance (or a load balanced instance). The URL needs to be formatted as: `http://dashboard_host:port`
	ConnectionString string `json:"connection_string"`

	// Set to `true` to enable filtering (sharding) of APIs.
	NodeIsSegmented bool `json:"node_is_segmented"`

	// The tags to use when filtering (sharding) Tyk Gateway nodes. Tags are processed as `OR` operations.
	// If you include a non-filter tag (e.g. an identifier such as `node-id-1`, this will become available to your Dashboard analytics).
	Tags []string `json:"tags"`
}

type StorageOptionsConf struct {
	// This should be set to `redis` (lowercase)
	Type string `json:"type"`
	// The Redis host, by default this is set to `localhost`, but for production this should be set to a cluster.
	Host string `json:"host"`
	// The Redis instance port.
	Port  int               `json:"port"`
	Hosts map[string]string `json:"hosts"` // Deprecated: Addrs instead.
	// If you have multi-node setup, you should use this field instead. For example: ["host1:port1", "host2:port2"].
	Addrs []string `json:"addrs"`
	// Redis sentinel master name
	MasterName string `json:"master_name"`
	// Redis sentinel password
	SentinelPassword string `json:"sentinel_password"`
	// Redis user name
	Username string `json:"username"`
	// If your Redis instance has a password set for access, you can set it here.
	Password string `json:"password"`
	// Redis database
	Database int `json:"database"`
	// Set the number of maximum idle connections in the Redis connection pool, which defaults to 100. Set to a higher value if you are expecting more traffic.
	MaxIdle int `json:"optimisation_max_idle"`
	// Set the number of maximum connections in the Redis connection pool, which defaults to 500. Set to a higher value if you are expecting more traffic.
	MaxActive int `json:"optimisation_max_active"`
	// Set a custom timeout for Redis network operations. Default value 5 seconds.
	Timeout int `json:"timeout"`
	// Enable Redis Cluster support
	EnableCluster bool `json:"enable_cluster"`
	// Enable SSL/TLS connection between your Tyk Gateway & Redis.
	UseSSL bool `json:"use_ssl"`
	// Disable TLS verification
	SSLInsecureSkipVerify bool `json:"ssl_insecure_skip_verify"`
}

type NormalisedURLConfig struct {
	// Set this to `true` to enable normalisation.
	Enabled bool `json:"enabled"`
	// Set this to true to have Tyk automatically clean up UUIDs. It will match the following styles:
	//
	// * `/15873a748894492162c402d67e92283b/search`
	// * `/CA761232-ED42-11CE-BACD-00AA0057B223/search`
	// * `/ca761232-ed42-11ce-BAcd-00aa0057b223/search`
	// * `/ca761232-ed42-11ce-BAcd-00aa0057b223/search`

	// Each UUID will be replaced with a placeholder {uuid}
	NormaliseUUIDs bool `json:"normalise_uuids"`

	// Set this to true to have Tyk automatically match for numeric IDs, it will match with a preceding slash so as not to capture actual numbers:
	NormaliseNumbers bool `json:"normalise_numbers"`

	// This is a list of custom patterns you can add. These must be valid regex strings. Tyk will replace these values with a {var} placeholder.
	Custom []string `json:"custom_patterns"`

	CompiledPatternSet NormaliseURLPatterns `json:"-"` // see analytics.go
}

type NormaliseURLPatterns struct {
	UUIDs  *regexp.Regexp
	IDs    *regexp.Regexp
	Custom []*regexp.Regexp
}

type AnalyticsConfigConfig struct {
	// Set empty for a Self-Managed installation or `rpc` for multi-cloud.
	Type string `json:"type"`

	// Adding IP addresses to this list will cause Tyk to ignore these IPs in the analytics data. These IP addresses will not produce an analytics log record.
	// This is useful for health checks and other samplers that might skew usage data.
	// The IP addresses must be provided as a JSON array, with the values being single IPs. CIDR values are not supported.
	IgnoredIPs []string `json:"ignored_ips"`

	// Set this value to `true` to have Tyk store the inbound request and outbound response data in HTTP Wire format as part of the Analytics data.
	// Please note, this will greatly increase your analytics DB size and can cause performance degradation on analytics processing by the Dashboard.
	// This setting can be overridden with an organisation flag, enabed at an API level, or on individual Key level.
	EnableDetailedRecording bool `json:"enable_detailed_recording"`

	// Tyk can store GeoIP information based on MaxMind DB’s to enable GeoIP tracking on inbound request analytics. Set this value to `true` and assign a DB using the `geo_ip_db_path` setting.
	EnableGeoIP bool `json:"enable_geo_ip"`

	// Path to a MaxMind GeoIP database
	// The analytics GeoIP DB can be replaced on disk. It will cleanly auto-reload every hour.
	GeoIPDBLocation string `json:"geo_ip_db_path"`

	// This section describes methods that enable you to normalise inbound URLs in your analytics to have more meaningful per-path data.
	NormaliseUrls NormalisedURLConfig `json:"normalise_urls"`

	// Number of workers used to process analytics. Defaults to number of CPU cores.
	PoolSize int `json:"pool_size"`

	// Number of records in analytics queue, per worker. Default: 1000.
	RecordsBufferSize uint64 `json:"records_buffer_size"`

	// You can set a time (in seconds) to configure how long analytics are kept if they are not processed. The default is 60 seconds.
	// This is used to prevent the potential infinite growth of Redis analytics storage.
	StorageExpirationTime int `json:"storage_expiration_time"`

	// Set this to `true` to have Tyk automatically divide the analytics records in multiple analytics keys.
	// This is especially useful when `storage.enable_cluster` is set to `true` since it will distribute the analytic keys across all the cluster nodes.
	EnableMultipleAnalyticsKeys bool `json:"enable_multiple_analytics_keys"`

	// You can set the interval length on how often the tyk Gateway will purge analytics data. This value is in seconds and defaults to 10 seconds.
	PurgeInterval float32 `json:"purge_interval"`

	ignoredIPsCompiled map[string]bool

	// Determines the serialization engine for analytics. Available options: msgpack, and protobuf. By default, msgpack.
	SerializerType string `json:"serializer_type"`
}

type HealthCheckConfig struct {
	// Setting this value to `true` will enable the health-check endpoint on /Tyk/health.
	EnableHealthChecks bool `json:"enable_health_checks"`

	// This setting defaults to 60 seconds. This is the time window that Tyk uses to sample health-check data.
	// You can set a higher value for more accurate data (a larger sample period), or a lower value for less accurate data.
	// The reason this value is configurable is because sample data takes up space in your Redis DB to store the data to calculate samples. On high-availability systems this may not be desirable and smaller values may be preferred.
	HealthCheckValueTimeout int64 `json:"health_check_value_timeouts"`
}

type LivenessCheckConfig struct {
	// Frequencies of performing interval healthchecks for Redis, Dashboard, and RPC layer. Default: 10 seconds.
	CheckDuration time.Duration `json:"check_duration"`
}

type DnsCacheConfig struct {
	// Setting this value to `true` will enable caching of DNS queries responses used for API endpoint’s host names. By default caching is disabled.
	Enabled bool `json:"enabled"`

	// This setting allows you to specify a duration in seconds before the record will be removed from cache after being added to it on the first DNS query resolution of API endpoints.
	// Setting `ttl` to `-1` prevents record from being expired and removed from cache on next check interval.
	TTL int64 `json:"ttl"`

	CheckInterval int64 `json:"-" ignored:"true"`
	//controls cache cleanup interval. By convention this shouldn't be exposed to a config or env_variable_setup

	// A strategy which will be used when a DNS query will reply with more than 1 IP Address per single host.
	// As a DNS query response IP Addresses can have a changing order depending on DNS server balancing strategy (eg: round robin, geographically dependent origin-ip ordering, etc) this option allows you to not to limit the connection to the first host in a cached response list or prevent response caching.
	//
	// * `pick_first` will instruct your Tyk Gateway to connect to the first IP in a returned IP list and cache the response.
	// * `random` will instruct your Tyk Gateway to connect to a random IP in a returned IP list and cache the response.
	// * `no_cache` will instruct your Tyk Gateway to connect to the first IP in a returned IP list and fetch each addresses list without caching on each API endpoint DNS query.
	MultipleIPsHandleStrategy IPsHandleStrategy `json:"multiple_ips_handle_strategy"`
}

type MonitorConfig struct {
	// Set this to `true` to have monitors enabled in your configuration for the node.
	EnableTriggerMonitors bool               `json:"enable_trigger_monitors"`
	Config                WebHookHandlerConf `json:"configuration"`
	// The trigger limit, as a percentage of the quota that must be reached in order to trigger the event, any time the quota percentage is increased the event will trigger.
	GlobalTriggerLimit float64 `json:"global_trigger_limit"`
	// Apply the monitoring subsystem to user keys.
	MonitorUserKeys bool `json:"monitor_user_keys"`
	// Apply the monitoring subsystem to organisation keys.
	MonitorOrgKeys bool `json:"monitor_org_keys"`
}

type WebHookHandlerConf struct {
	// The method to use for the webhook.
	Method string `bson:"method" json:"method"`
	// The target path on which to send the request.
	TargetPath string `bson:"target_path" json:"target_path"`
	// The template to load in order to format the request.
	TemplatePath string `bson:"template_path" json:"template_path"`
	// Headers to set when firing the webhook.
	HeaderList map[string]string `bson:"header_map" json:"header_map"`
	// The cool-down for the event so it does not trigger again (in seconds).
	EventTimeout int64 `bson:"event_timeout" json:"event_timeout"`
}

type SlaveOptionsConfig struct {
	// Set to `true` to connect a worker Gateway using RPC.
	UseRPC bool `json:"use_rpc"`

	// Set this option to `true` to use an SSL RPC connection.
	UseSSL bool `json:"use_ssl"`

	// Set this option to `true` to allow the certificate validation (certificate chain and hostname) to be skipped.
	// This can be useful if you use a self-signed certificate.
	SSLInsecureSkipVerify bool `json:"ssl_insecure_skip_verify"`

	// Use this setting to add the URL for your MDCB or load balancer host.
	ConnectionString string `json:"connection_string"`

	// Your organisation ID to connect to the MDCB installation.
	RPCKey string `json:"rpc_key"`

	// This the API key of a user used to authenticate and authorise the Gateway’s access through MDCB.
	// The user should be a standard Dashboard user with minimal privileges so as to reduce any risk if the user is compromised.
	// The suggested security settings are read for Real-time notifications and the remaining options set to deny.
	APIKey string `json:"api_key"`

	// Set this option to `true` to enable RPC caching for keys.
	EnableRPCCache bool `json:"enable_rpc_cache"`

	// For an Self-Managed installation this can be left at `false` (the default setting). For Legacy Cloud Gateways it must be set to ‘true’.
	BindToSlugsInsteadOfListenPaths bool `json:"bind_to_slugs"`

	// Set this option to `true` if you don’t want to monitor changes in the keys from a master Gateway.
	DisableKeySpaceSync bool `json:"disable_keyspace_sync"`

	// This is the `zone` that this instance inhabits, e.g. the cluster/data-centre the Gateway lives in.
	// The group ID must be the same across all the Gateways of a data-centre/cluster which are also sharing the same Redis instance.
	// This ID should also be unique per cluster (otherwise another Gateway cluster can pick up your keyspace events and your cluster will get zero updates).
	GroupID string `json:"group_id"`

	// Call Timeout allows to specify a time in seconds for the maximum allowed duration of a RPC call.
	CallTimeout int `json:"call_timeout"`

	// The maximum time in seconds that a RPC ping can last.
	PingTimeout int `json:"ping_timeout"`

	// The number of RPC connections in the pool. Basically it creates a set of connections that you can re-use as needed.
	RPCPoolSize int `json:"rpc_pool_size"`

	// You can use this to set a period for which the Gateway will check if there are changes in keys that must be synchronized. If this value is not set then it will default to 10 seconds.
	KeySpaceSyncInterval float32 `json:"key_space_sync_interval"`

	// RPCCertCacheExpiration defines the expiration time of the rpc cache that stores the certificates, defined in seconds
	RPCCertCacheExpiration float32 `json:"rpc_cert_cache_expiration"`

	// RPCKeysCacheExpiration defines the expiration time of the rpc cache that stores the keys, defined in seconds
	RPCGlobalCacheExpiration float32 `json:"rpc_global_cache_expiration"`

	// SynchroniserEnabled enable this config if MDCB has enabled the synchoniser. If disabled then it will ignore signals to synchonise recources
	SynchroniserEnabled bool `json:"synchroniser_enabled"`
}

type LocalSessionCacheConf struct {
	// By default sessions are set to cache. Set this to `true` to stop Tyk from caching keys locally on the node.
	DisableCacheSessionState bool `json:"disable_cached_session_state"`

	CachedSessionTimeout int `json:"cached_session_timeout"`
	CacheSessionEviction int `json:"cached_session_eviction"`
}
type CertsData []CertData

func (certs *CertsData) Decode(value string) error {
	err := json.Unmarshal([]byte(value), certs)
	if err != nil {
		log.Error("Error unmarshalling TYK_GW_HTTPSERVEROPTIONS_CERTIFICATES: ", err)
		return err
	}
	return nil
}

type HttpServerOptionsConfig struct {
	// No longer used
	OverrideDefaults bool `json:"-"`

	// API Consumer -> Gateway network read timeout. Not setting this config, or setting this to 0, defaults to 120 seconds
	ReadTimeout int `json:"read_timeout"`

	// API Consumer -> Gateway network write timeout. Not setting this config, or setting this to 0, defaults to 120 seconds
	WriteTimeout int `json:"write_timeout"`

	// Set to true to enable SSL connections
	UseSSL bool `json:"use_ssl"`

	// Enable Lets-Encrypt support
	UseLE_SSL bool `json:"use_ssl_le"`

	// Enable HTTP2 protocol handling
	EnableHttp2 bool `json:"enable_http2"`

	// EnableStrictRoutes changes the routing to avoid nearest-neighbour requests on overlapping routes
	//
	// - if disabled, `/apple` will route to `/app`, the current default behavior,
	// - if enabled, `/app` only responds to `/app`, `/app/` and `/app/*` but not `/apple`
	//
	// Regular expressions and parameterized routes will be left alone regardless of this setting.
	EnableStrictRoutes bool `json:"enable_strict_routes"`

	// Disable TLS verification. Required if you are using self-signed certificates.
	SSLInsecureSkipVerify bool `json:"ssl_insecure_skip_verify"`

	// Enabled WebSockets and server side events support
	EnableWebSockets bool `json:"enable_websockets"`

	// Deprecated. SSL certificates used by Gateway server.
	Certificates CertsData `json:"certificates"`

	// SSL certificates used by your Gateway server. A list of certificate IDs or path to files.
	SSLCertificates []string `json:"ssl_certificates"`

	// Start your Gateway HTTP server on specific server name
	ServerName string `json:"server_name"`

	// Minimum TLS version. Possible values: https://tyk.io/docs/basic-config-and-security/security/tls-and-ssl/#values-for-tls-versions
	MinVersion uint16 `json:"min_version"`

	// Maximum TLS version.
	MaxVersion uint16 `json:"max_version"`

	// Set this to the number of seconds that Tyk uses to flush content from the proxied upstream connection to the open downstream connection.
	// This option needed be set for streaming protocols like Server Side Events, or gRPC streaming.
	FlushInterval int `json:"flush_interval"`

	// Allow the use of a double slash in a URL path. This can be useful if you need to pass raw URLs to your API endpoints.
	// For example: `http://myapi.com/get/http://example.com`.
	SkipURLCleaning bool `json:"skip_url_cleaning"`

	// Disable automatic character escaping, allowing to path original URL data to the upstream.
	SkipTargetPathEscaping bool `json:"skip_target_path_escaping"`

	// Custom SSL ciphers. See list of ciphers here https://tyk.io/docs/basic-config-and-security/security/tls-and-ssl/#specify-tls-cipher-suites-for-tyk-gateway--tyk-dashboard
	Ciphers []string `json:"ssl_ciphers"`
}

type AuthOverrideConf struct {
	ForceAuthProvider    bool                       `json:"force_auth_provider"`
	AuthProvider         apidef.AuthProviderMeta    `json:"auth_provider"`
	ForceSessionProvider bool                       `json:"force_session_provider"`
	SessionProvider      apidef.SessionProviderMeta `json:"session_provider"`
}

type UptimeTestsConfigDetail struct {
	// The sample size to trigger a `HostUp` or `HostDown` event. For example, a setting of 3 will require at least three failures to occur before the uptime test is triggered.
	FailureTriggerSampleSize int `json:"failure_trigger_sample_size"`
	// The value in seconds between tests runs. All tests will run simultaneously. This value will set the time between those tests. So a value of 60 will run all uptime tests every 60 seconds.
	TimeWait int `json:"time_wait"`
	// The goroutine pool size to keep idle for uptime tests. If you have many uptime tests running at a high time period, then increase this value.
	CheckerPoolSize int `json:"checker_pool_size"`
	// Set this value to `true` to have the node capture and record analytics data regarding the uptime tests.
	EnableUptimeAnalytics bool `json:"enable_uptime_analytics"`
}

type UptimeTestsConfig struct {
	// To disable uptime tests on this node, set this value to `true`.
	Disable bool `json:"disable"`
	// If you have multiple Gateway clusters connected to the same Redis instance, you need to set a unique poller group for each cluster.
	PollerGroup string                  `json:"poller_group"`
	Config      UptimeTestsConfigDetail `json:"config"`
}
type ServiceDiscoveryConf struct {
	// Service discovery cache timeout
	DefaultCacheTimeout int `json:"default_cache_timeout"`
}

type CoProcessConfig struct {
	// Enable gRPC and Python plugins
	EnableCoProcess bool `json:"enable_coprocess"`

	// Address of gRPC user
	CoProcessGRPCServer string `json:"coprocess_grpc_server"`

	// Maximum message which can be received from a gRPC server
	GRPCRecvMaxSize int `json:"grpc_recv_max_size"`

	// Maximum message which can be sent to gRPC server
	GRPCSendMaxSize int `json:"grpc_send_max_size"`

	// Sets the path to built-in Tyk modules. This will be part of the Python module lookup path. The value used here is the default one for most installations.
	PythonPathPrefix string `json:"python_path_prefix"`

	// If you have multiple Python versions installed you can specify your version.
	PythonVersion string `json:"python_version"`
}

type CertificatesConfig struct {
	API []string `json:"apis"`
	// Specify upstream mutual TLS certificates at a global level in the following format: `{ "<host>": "<cert>" }``
	Upstream map[string]string `json:"upstream"`
	// Certificates used for Control API Mutual TLS
	ControlAPI []string `json:"control_api"`
	// Used for communicating with the Dashboard if it is configured to use Mutual TLS
	Dashboard []string `json:"dashboard_api"`
	// Certificates used for MDCB Mutual TLS
	MDCB []string `json:"mdcb_api"`
}

type SecurityConfig struct {
	// Set the AES256 secret which is used to encode certificate private keys when they uploaded via certificate storage
	PrivateCertificateEncodingSecret string `json:"private_certificate_encoding_secret"`

	// Enable Gateway Control API to use Mutual TLS. Certificates can be set via `security.certificates.control_api` section
	ControlAPIUseMutualTLS bool `json:"control_api_use_mutual_tls"`

	// Specify public keys used for Certificate Pinning on global level.
	PinnedPublicKeys map[string]string `json:"pinned_public_keys"`

	Certificates CertificatesConfig `json:"certificates"`
}

type NewRelicConfig struct {
	// New Relic Application name
	AppName string `json:"app_name"`
	// New Relic License key
	LicenseKey string `json:"license_key"`
}

type Tracer struct {
	// The name of the tracer to initialize. For instance appdash, to use appdash tracer
	Name string `json:"name"`

	// Enable tracing
	Enabled bool `json:"enabled"`

	// Tracing configuration. Refer to the Tracing Docs for the full list of options.
	Options map[string]interface{} `json:"options"`
}

// ServicePort defines a protocol and port on which a service can bind to.
type ServicePort struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

// PortWhiteList defines ports that will be allowed by the Gateway.
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

type PortsWhiteList map[string]PortWhiteList

func (pwl *PortsWhiteList) Decode(value string) error {
	err := json.Unmarshal([]byte(value), pwl)
	if err != nil {
		log.Error("Error unmarshalling TYK_GW_PORTWHITELIST: ", err)
		return err
	}

	return nil
}

// Config is the configuration object used by Tyk to set up various parameters.
type Config struct {
	// OriginalPath is the path to the config file that is read. If
	// none was found, it's the path to the default config file that
	// was written.
	OriginalPath string `json:"-"`

	// Force your Gateway to work only on a specific domain name. Can be overridden by API custom domain.
	HostName string `json:"hostname"`

	// If your machine has multiple network devices or IPs you can force the Gateway to use the IP address you want.
	ListenAddress string `json:"listen_address"`

	// Setting this value will change the port that Tyk listens on. Default: 8080.
	ListenPort int `json:"listen_port"`

	// Custom hostname for the Control API
	ControlAPIHostname string `json:"control_api_hostname"`

	// Set to run your Gateway Control API on a separate port, and protect it behind a firewall if needed. Please make sure you follow this guide when setting the control port https://tyk.io/docs/planning-for-production/#change-your-control-port.
	ControlAPIPort int `json:"control_api_port"`

	// This should be changed as soon as Tyk is installed on your system.
	// This value is used in every interaction with the Tyk Gateway API. It should be passed along as the X-Tyk-Authorization header in any requests made.
	// Tyk assumes that you are sensible enough not to expose the management endpoints publicly and to keep this configuration value to yourself.
	Secret string `json:"secret"`

	// The shared secret between the Gateway and the Dashboard to ensure that API Definition downloads, heartbeat and Policy loads are from a valid source.
	NodeSecret string `json:"node_secret"`

	// Linux PID file location. Do not change unless you know what you are doing. Default: /var/run/tyk/tyk-gateway.pid
	PIDFileLocation string `json:"pid_file_location"`

	// Can be set to disable Dashboard message signature verification. When set to `true`, `public_key_path` can be ignored.
	AllowInsecureConfigs bool `json:"allow_insecure_configs"`

	// While communicating with the Dashboard. By default, all messages are signed by a private/public key pair. Set path to public key.
	PublicKeyPath string `json:"public_key_path"`

	// Allow your Dashboard to remotely set Gateway configuration via the Nodes screen.
	AllowRemoteConfig bool `bson:"allow_remote_config" json:"allow_remote_config"`

	// Global Certificate configuration
	Security SecurityConfig `json:"security"`

	// Gateway HTTP server configuration
	HttpServerOptions HttpServerOptionsConfig `json:"http_server_options"`

	// Expose version header with a given name. Works only for versioned APIs.
	VersionHeader string `json:"version_header"`

	// Disable dynamic API and Policy reloads, e.g. it will load new changes only on procecss start.
	SuppressRedisSignalReload bool `json:"suppress_redis_signal_reload"`

	// Enable Key hashing
	HashKeys bool `json:"hash_keys"`

	// Specify the Key hashing algorithm. Possible values: murmur64, murmur128, sha256.
	HashKeyFunction string `json:"hash_key_function"`

	// Specify the Key hashing algorithm for "basic auth". Possible values: murmur64, murmur128, sha256, bcrypt.
	// Will default to "bcrypt" if not set.
	BasicAuthHashKeyFunction string `json:"basic_auth_hash_key_function"`

	// Specify your previous key hashing algorithm if you migrated from one algorithm to another.
	HashKeyFunctionFallback []string `json:"hash_key_function_fallback"`

	// Allows the listing of hashed API keys
	EnableHashedKeysListing bool `json:"enable_hashed_keys_listing"`

	// Minimum API token length
	MinTokenLength int `json:"min_token_length"`

	// Path to error and webhook templates. Defaults to the current binary path.
	TemplatePath string `json:"template_path"`

	// The policies section allows you to define where Tyk can find its policy templates. Policy templates are similar to key definitions in that they allow you to set quotas, access rights and rate limits for keys.
	// Policies are loaded when Tyk starts and if changed require a hot-reload so they are loaded into memory.
	// A policy can be defined in a file (Open Source installations) or from the same database as the Dashboard.
	Policies PoliciesConfig `json:"policies"`

	// Defines the ports that will be available for the API services to bind to in the following format: `"{“":“”}"`. Remember to escape JSON strings.
	// This is a map of protocol to PortWhiteList. This allows per protocol
	// configurations.
	PortWhiteList PortsWhiteList `json:"ports_whitelist"`

	// Disable port whilisting, essentially allowing you to use any port for your API.
	DisablePortWhiteList bool `json:"disable_ports_whitelist"`

	// If Tyk is being used in its standard configuration (Open Source installations), then API definitions are stored in the apps folder (by default in /opt/tyk-gateway/apps).
	// This location is scanned for .json files and re-scanned at startup or reload.
	// See the API section of the Tyk Gateway API for more details.
	AppPath string `json:"app_path"`

	// If you are a Tyk Pro user, this option will enable polling the Dashboard service for API definitions.
	// On startup Tyk will attempt to connect and download any relevant application configurations from from your Dashboard instance.
	// The files are exactly the same as the JSON files on disk with the exception of a BSON ID supplied by the Dashboard service.
	UseDBAppConfigs bool `json:"use_db_app_configs"`

	// This section defines API loading and shard options. Enable these settings to selectively load API definitions on a node from your Dashboard service.
	DBAppConfOptions DBAppConfOptionsConfig `json:"db_app_conf_options"`

	// This section defines your Redis configuration.
	Storage StorageOptionsConf `json:"storage"`

	// Disable the capability of the Gateway to `autodiscover` the Dashboard through heartbeat messages via Redis.
	// The goal of zeroconf is auto-discovery, so you do not have to specify the Tyk Dashboard address in your Gateway`tyk.conf` file.
	// In some specific cases, for example, when the Dashboard is bound to a public domain, not accessible inside an internal network, or similar, `disable_dashboard_zeroconf` can be set to `true`, in favour of directly specifying a Tyk Dashboard address.
	DisableDashboardZeroConf bool `json:"disable_dashboard_zeroconf"`

	// The `slave_options` allow you to configure the RPC slave connection required for MDCB installations.
	// These settings must be configured for every RPC slave/worker node.
	SlaveOptions SlaveOptionsConfig `json:"slave_options"`

	// If set to `true`, distributed rate limiter will be disabled for this node, and it will be excluded from any rate limit calculation.
	//
	// Note:
	//   If you set `db_app_conf_options.node_is_segmented` to `true` for multiple Gateway nodes, you should ensure that `management_node` is set to `false`.
	//   This is to ensure visibility for the management node across all APIs.
	ManagementNode bool `json:"management_node"`

	// This is used as part of the RPC / Hybrid back-end configuration in a Tyk Enterprise installation and isn’t used anywhere else.
	AuthOverride AuthOverrideConf `json:"auth_override"`

	// Redis based rate limiter with fixed window. Provides 100% rate limiting accuracy, but require two additional Redis roundtrip for each request.
	EnableRedisRollingLimiter bool `json:"enable_redis_rolling_limiter"`

	// To enable, set to `true`. The sentinel-based rate limiter delivers a smoother performance curve as rate-limit calculations happen off-thread, but a stricter time-out based cool-down for clients. For example, when a throttling action is triggered, they are required to cool-down for the period of the rate limit.
	// Disabling the sentinel based rate limiter will make rate-limit calculations happen on-thread and therefore offers a staggered cool-down and a smoother rate-limit experience for the client.
	// For example, you can slow your connection throughput to regain entry into your rate limit. This is more of a “throttle” than a “block”.
	// The standard rate limiter offers similar performance as the sentinel-based limiter. This is disabled by default.
	EnableSentinelRateLimiter bool `json:"enable_sentinel_rate_limiter"`

	// An enhancement for the Redis and Sentinel rate limiters, that offers a significant improvement in performance by not using transactions on Redis rate-limit buckets.
	EnableNonTransactionalRateLimiter bool `json:"enable_non_transactional_rate_limiter"`

	// How frequently a distributed rate limiter synchronises information between the Gateway nodes. Default: 2 seconds.
	DRLNotificationFrequency int `json:"drl_notification_frequency"`

	// A distributed rate limiter is inaccurate on small rate limits, and it will fallback to a Redis or Sentinel rate limiter on an individual user basis, if its rate limiter lower then threshold.
	// A Rate limiter threshold calculated using the following formula: `rate_threshold = drl_threshold * number_of_gateways`.
	// So you have 2 Gateways, and your threshold is set to 5, if a user rate limit is larger than 10, it will use the distributed rate limiter algorithm.
	// Default: 5
	DRLThreshold float64 `json:"drl_threshold"`

	// Controls which algorthm to use as a fallback when your distributed rate limiter can't be used.
	DRLEnableSentinelRateLimiter bool `json:"drl_enable_sentinel_rate_limiter"`

	// Allows you to dynamically configure analytics expiration on a per organisation level
	EnforceOrgDataAge bool `json:"enforce_org_data_age"`

	// Allows you to dynamically configure detailed logging on a per organisation level
	EnforceOrgDataDetailLogging bool `json:"enforce_org_data_detail_logging"`

	// Allows you to dynamically configure organisation quotas on a per organisation level
	EnforceOrgQuotas bool `json:"enforce_org_quotas"`

	ExperimentalProcessOrgOffThread bool `json:"experimental_process_org_off_thread"`

	// The monitor section is useful if you wish to enforce a global trigger limit on organisation and user quotas.
	// This feature will trigger a webhook event to fire when specific triggers are reached.
	// Triggers can be global (set in the node), by organisation (set in the organisation session object) or by key (set in the key session object)
	//
	// While Organisation-level and Key-level triggers can be tiered (e.g. trigger at 10%, trigger at 20%, trigger at 80%), in the node-level configuration only a global value can be set.
	// If a global value and specific trigger level are the same the trigger will only fire once:
	//
	// ```
	// "monitor": {
	//   "enable_trigger_monitors": true,
	//   "configuration": {
	//    "method": "POST",
	//    "target_path": "http://domain.com/notify/quota-trigger",
	//    "template_path": "templates/monitor_template.json",
	//    "header_map": {
	//      "some-secret": "89787855"
	//    },
	//    "event_timeout": 10
	//  },
	//  "global_trigger_limit": 80.0,
	//  "monitor_user_keys": false,
	//  "monitor_org_keys": true
	// },
	// ```
	Monitor MonitorConfig `json:"monitor"`

	// Maximum idle connections, per API, between Tyk and Upstream. By default not limited.
	MaxIdleConns int `bson:"max_idle_connections" json:"max_idle_connections"`
	// Maximum idle connections, per API, per upstream, between Tyk and Upstream. Default:100
	MaxIdleConnsPerHost int `bson:"max_idle_connections_per_host" json:"max_idle_connections_per_host"`
	// Maximum connection time. If set it will force gateway reconnect to the upstream.
	MaxConnTime int64 `json:"max_conn_time"`

	// If set, disable keepalive between User and Tyk
	CloseConnections bool `json:"close_connections"`

	// Allows you to use custom domains
	EnableCustomDomains bool `json:"enable_custom_domains"`

	// If AllowMasterKeys is set to true, session objects (key definitions) that do not have explicit access rights set
	// will be allowed by Tyk. This means that keys that are created have access to ALL APIs, which in many cases is
	// unwanted behaviour unless you are sure about what you are doing.
	AllowMasterKeys bool `json:"allow_master_keys"`

	ServiceDiscovery ServiceDiscoveryConf `json:"service_discovery"`

	// Globally ignore TLS verification between Tyk and your Upstream services
	ProxySSLInsecureSkipVerify bool `json:"proxy_ssl_insecure_skip_verify"`

	// Enable HTTP2 support between Tyk and your upstream service. Required for gRPC.
	ProxyEnableHttp2 bool `json:"proxy_enable_http2"`

	// Minimum TLS version for connection between Tyk and your upstream service.
	ProxySSLMinVersion uint16 `json:"proxy_ssl_min_version"`

	// Maximum TLS version for connection between Tyk and your upstream service.
	ProxySSLMaxVersion uint16 `json:"proxy_ssl_max_version"`

	// Whitelist ciphers for connection between Tyk and your upstream service.
	ProxySSLCipherSuites []string `json:"proxy_ssl_ciphers"`

	// This can specify a default timeout in seconds for upstream API requests.
	ProxyDefaultTimeout float64 `json:"proxy_default_timeout"`

	// Disable TLS renegotiation.
	ProxySSLDisableRenegotiation bool `json:"proxy_ssl_disable_renegotiation"`

	// Disable keepalives between Tyk and your upstream service.
	// Set this value to `true` to force Tyk to close the connection with the server, otherwise the connections will remain open for as long as your OS keeps TCP connections open.
	// This can cause a file-handler limit to be exceeded. Setting to false can have performance benefits as the connection can be reused.
	ProxyCloseConnections bool `json:"proxy_close_connections"`

	// Tyk nodes can provide uptime awareness, uptime testing and analytics for your underlying APIs uptime and availability.
	// Tyk can also notify you when a service goes down.
	UptimeTests UptimeTestsConfig `json:"uptime_tests"`

	// This section enables the configuration of the health-check API endpoint and the size of the sample data cache (in seconds).
	HealthCheck HealthCheckConfig `json:"health_check"`

	// Enables you to rename the /hello endpoint
	HealthCheckEndpointName string `json:"health_check_endpoint_name"`

	// Change the expiry time of a refresh token. By default 14 days (in seconds).
	OauthRefreshExpire int64 `json:"oauth_refresh_token_expire"`

	// Change the expiry time of OAuth tokens (in seconds).
	OauthTokenExpire int32 `json:"oauth_token_expire"`

	// Specifies how long expired tokens are stored in Redis. The value is in seconds and the default is 0. Using the default means expired tokens are never removed from Redis.
	OauthTokenExpiredRetainPeriod int32 `json:"oauth_token_expired_retain_period"`

	// Character which should be used as a separator for OAuth redirect URI URLs. Default: ;.
	OauthRedirectUriSeparator string `json:"oauth_redirect_uri_separator"`

	// Configures the OAuth error status code returned. If not set, it defaults to a 403 error.
	OauthErrorStatusCode int `json:"oauth_error_status_code"`

	// By default all key IDs in logs are hidden. Set to `true` if you want to see them for debugging reasons.
	EnableKeyLogging bool `json:"enable_key_logging"`

	// Force the validation of the hostname against the common name, even if TLS verification is disabled.
	SSLForceCommonNameCheck bool `json:"ssl_force_common_name_check"`

	// Tyk is capable of recording every hit to your API to a database with various filtering parameters. Set this value to `true` and fill in the sub-section below to enable logging.
	//
	// Note:
	//   For performance reasons, Tyk will store traffic data to Redis initially and then purge the data from Redis to MongoDB or other data stores on a regular basis as determined by the purge_delay setting in your Tyk Pump configuration.
	EnableAnalytics bool `json:"enable_analytics"`

	// This section defines options on what analytics data to store.
	AnalyticsConfig AnalyticsConfigConfig `json:"analytics_config"`

	// Enable separate analytics storage. Used together with `analytics_storage`.
	EnableSeperateAnalyticsStore bool               `json:"enable_separate_analytics_store"`
	AnalyticsStorage             StorageOptionsConf `json:"analytics_storage"`

	LivenessCheck LivenessCheckConfig `json:"liveness_check"`

	// This section enables the global configuration of the expireable DNS records caching for your Gateway API endpoints.
	// By design caching affects only http(s), ws(s) protocols APIs and doesn’t affect any plugin/middleware DNS queries.
	//
	// ```
	// "dns_cache": {
	//   "enabled": true, //Turned off by default
	//   "ttl": 60, //Time in seconds before the record will be removed from cache
	//   "multiple_ips_handle_strategy": "random" //A strategy, which will be used when dns query will reply with more than 1 ip address per single host.
	// }
	// ```
	DnsCache DnsCacheConfig `json:"dns_cache"`

	// If set to `true` this allows you to disable the regular expression cache. The default setting is `false`.
	DisableRegexpCache bool `json:"disable_regexp_cache"`

	// If you set `disable_regexp_cache` to `false`, you can use this setting to limit how long the regular expression cache is kept for in seconds.
	// The default is 60 seconds. This must be a positive value. If you set to 0 this uses the default value.
	RegexpCacheExpire int32 `json:"regexp_cache_expire"`

	// Tyk can cache some data locally, this can speed up lookup times on a single node and lower the number of connections and operations being done on Redis. It will however introduce a slight delay when updating or modifying keys as the cache must expire.
	// This does not affect rate limiting.
	LocalSessionCache LocalSessionCacheConf `json:"local_session_cache"`

	// Enable to use a separate Redis for cache storage
	EnableSeperateCacheStore bool               `json:"enable_separate_cache_store"`
	CacheStorage             StorageOptionsConf `json:"cache_storage"`

	// Enable downloading Plugin bundles
	// Example:
	// ```
	// "enable_bundle_downloader": true,
	// "bundle_base_url": "http://my-bundle-server.com/bundles/",
	// "public_key_path": "/path/to/my/pubkey",
	// ```
	EnableBundleDownloader bool `bson:"enable_bundle_downloader" json:"enable_bundle_downloader"`

	// Is a base URL that will be used to download the bundle. In this example we have `bundle-latest.zip` specified in the API settings, Tyk will fetch the following URL: http://my-bundle-server.com/bundles/bundle-latest.zip (see the next section for details).
	BundleBaseURL string `bson:"bundle_base_url" json:"bundle_base_url"`

	// Disable TLS validation for bundle URLs
	BundleInsecureSkipVerify bool `bson:"bundle_insecure_skip_verify" json:"bundle_insecure_skip_verify"`

	// Set to true if you are using JSVM custom middleware or virtual endpoints.
	EnableJSVM bool `json:"enable_jsvm"`

	// Set the execution timeout for JSVM plugins and virtal endpoints
	JSVMTimeout int `json:"jsvm_timeout"`

	// Disable virtual endpoints and the code will not be loaded into the VM when the API definition initialises.
	// This is useful for systems where you want to avoid having third-party code run.
	DisableVirtualPathBlobs bool `json:"disable_virtual_path_blobs"`

	// Path to the JavaScript file which will be pre-loaded for any JSVM middleware or virtual endpoint. Useful for defining global shared functions.
	TykJSPath string `json:"tyk_js_path"`

	// Path to the plugins dirrectory. By default is ``./middleware`.
	MiddlewarePath string `json:"middleware_path"`

	// Configuration options for Python and gRPC plugins.
	CoProcessOptions CoProcessConfig `json:"coprocess_options"`

	// Ignore the case of any endpoints for APIs managed by Tyk. Setting this to `true` will override any individual API and Ignore, Blacklist and Whitelist plugin endpoint settings.
	IgnoreEndpointCase bool `json:"ignore_endpoint_case"`

	// When enabled Tyk ignores the canonical format of the MIME header keys.
	//
	// For example when a request header with a “my-header” key is injected using “global_headers”, the upstream would typically get it as “My-Header”. When this flag is enabled it will be sent as “my-header” instead.
	//
	// Current support is limited to JavaScript plugins, global header injection, virtual endpoint and JQ transform header rewrites.
	// This functionality doesn’t affect headers that are sent by the HTTP client and the default formatting will apply in this case.
	//
	// For technical details refer to the [CanonicalMIMEHeaderKey](https://golang.org/pkg/net/textproto/#CanonicalMIMEHeaderKey) functionality in the Go documentation.
	IgnoreCanonicalMIMEHeaderKey bool `json:"ignore_canonical_mime_header_key"`

	// You can now set a logging level (log_level). The following levels can be set: debug, info, warn, error.
	// If not set or left empty, it will default to `info`.
	LogLevel string `json:"log_level"`

	// Section for configuring OpenTracing support
	Tracer Tracer `json:"tracing"`

	NewRelic NewRelicConfig `json:"newrelic"`

	// Enable debugging of your Tyk Gateway by exposing profiling information through https://tyk.io/docs/troubleshooting/tyk-gateway/profiling/
	HTTPProfile bool `json:"enable_http_profiler"`

	// Enables the real-time Gateway log view in the Dashboard.
	UseRedisLog bool `json:"use_redis_log"`

	// Enable Sentry logging
	UseSentry bool `json:"use_sentry"`
	// Sentry API code
	SentryCode string `json:"sentry_code"`
	// Log verbosity for Sentry logging
	SentryLogLevel string `json:"sentry_log_level"`

	// Enable Syslog log output
	UseSyslog bool `json:"use_syslog"`
	// Syslong transport to use. Values: tcp or udp.
	SyslogTransport string `json:"syslog_transport"`
	// Graylog server address
	SyslogNetworkAddr string `json:"syslog_network_addr"`

	// Use Graylog log output
	UseGraylog bool `json:"use_graylog"`
	// Graylog server address
	GraylogNetworkAddr string `json:"graylog_network_addr"`

	// Use logstash log output
	UseLogstash bool `json:"use_logstash"`
	// Logstash network transport. Values: tcp or udp.
	LogstashTransport string `json:"logstash_transport"`
	// Logstash server address
	LogstashNetworkAddr string `json:"logstash_network_addr"`

	// Show 404 HTTP errors in your Gateway application logs
	Track404Logs bool `json:"track_404_logs"`

	// Address of StatsD server. If set enable statsd monitoring.
	StatsdConnectionString string `json:"statsd_connection_string"`
	// StatsD prefix
	StatsdPrefix string `json:"statsd_prefix"`

	// Event System
	EventHandlers        apidef.EventHandlerMetaConfig         `json:"event_handlers"`
	EventTriggers        map[apidef.TykEvent][]TykEventHandler `json:"event_trigers_defunct"`  // Deprecated: Config.GetEventTriggers instead.
	EventTriggersDefunct map[apidef.TykEvent][]TykEventHandler `json:"event_triggers_defunct"` // Deprecated: Config.GetEventTriggers instead.

	// HideGeneratorHeader will mask the 'X-Generator' and 'X-Mascot-...' headers, if set to true.
	HideGeneratorHeader bool `json:"hide_generator_header"`

	SupressDefaultOrgStore         bool `json:"suppress_default_org_store"`
	LegacyEnableAllowanceCountdown bool `bson:"legacy_enable_allowance_countdown" json:"legacy_enable_allowance_countdown"`

	// Enable global API token expiration. Can be needed if all your APIs using JWT or oAuth 2.0 auth methods with dynamically generated keys.
	ForceGlobalSessionLifetime bool `bson:"force_global_session_lifetime" json:"force_global_session_lifetime"`
	// SessionLifetimeRespectsKeyExpiration respects the key expiration time when the session lifetime is less than the key expiration. That is, Redis waits the key expiration for physical removal.
	SessionLifetimeRespectsKeyExpiration bool `bson:"session_lifetime_respects_key_expiration" json:"session_lifetime_respects_key_expiration"`
	// global session lifetime, in seconds.
	GlobalSessionLifetime int64 `bson:"global_session_lifetime" json:"global_session_lifetime"`

	// This section enables the use of the KV capabilities to substitute configuration values.
	// See more details https://tyk.io/docs/tyk-configuration-reference/kv-store/
	KV struct {
		Consul ConsulConfig `json:"consul"`
		Vault  VaultConfig  `json:"vault"`
	} `json:"kv"`

	// Secrets are key-value pairs that can be accessed in the dashboard via "secrets://"
	Secrets map[string]string `json:"secrets"`

	// Override the default error code and or message returned by middleware.
	// The following message IDs can be used to override the message and error codes:
	//
	// AuthToken message IDs
	// * `auth.auth_field_missing`
	// * `auth.key_not_found`
	//
	// OIDC message IDs
	// * `oauth.auth_field_missing`
	// * `oauth.auth_field_malformed`
	// * `oauth.key_not_found`
	// * `oauth.client_deleted`
	//
	// Sample Override Message Setting
	// ```
	// "override_messages": {
	//   "oauth.auth_field_missing" : {
	//    "code": 401,
	//    "message": "Token is not authorised"
	//  }
	// }
	// ```
	OverrideMessages map[string]TykError `bson:"override_messages" json:"override_messages"`

	// Cloud flag shows the Gateway runs in Tyk-cloud.
	Cloud bool `json:"cloud"`

	// Skip TLS verification for JWT JWKs url validation
	JWTSSLInsecureSkipVerify bool `json:"jwt_ssl_insecure_skip_verify"`
}

type TykError struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// VaultConfig is used to configure the creation of a client
// This is a stripped down version of the config structure in vault's API client
type VaultConfig struct {
	// Address is the address of the Vault server. This should be a complete
	// URL such as "http://vault.example.com".
	Address string `json:"address"`

	// AgentAddress is the address of the local Vault agent. This should be a
	// complete URL such as "http://vault.example.com".
	AgentAddress string `json:"agent_address"`

	// MaxRetries controls the maximum number of times to retry when a vault
	// serer occurs
	MaxRetries int `json:"max_retries"`

	Timeout time.Duration `json:"timeout"`

	// Token is the vault root token
	Token string `json:"token"`

	// KVVersion is the version number of Vault. Usually defaults to 2
	KVVersion int `json:"kv_version"`
}

// ConsulConfig is used to configure the creation of a client
// This is a stripped down version of the Config struct in consul's API client
type ConsulConfig struct {
	// Address is the address of the Consul server
	Address string `json:"address"`

	// Scheme is the URI scheme for the Consul server
	Scheme string `json:"scheme"`

	// The datacenter to use. If not provided, the default agent datacenter is used.
	Datacenter string `json:"datacenter"`

	// HttpAuth is the auth info to use for http access.
	HttpAuth struct {
		// Username to use for HTTP Basic Authentication
		Username string `json:"username"`

		// Password to use for HTTP Basic Authentication
		Password string `json:"password"`
	} `json:"http_auth"`

	// WaitTime limits how long a Watch will block. If not provided,
	// the agent default values will be used.
	WaitTime time.Duration `json:"wait_time"`

	// Token is used to provide a per-request ACL token
	// which overrides the agent's default token.
	Token string `json:"token"`

	// TLS configuration
	TLSConfig struct {
		// Address
		Address string `json:"address"`
		// CA file
		CAFile string `json:"ca_file"`
		// CA Path
		CAPath string `json:"ca_path"`
		// Cert file
		CertFile string `json:"cert_file"`
		// Key file
		KeyFile string `json:"key_file"`
		// Disable TLS validation
		InsecureSkipVerify bool `json:"insecure_skip_verify"`
	} `json:"tls_config"`
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
	// Domain name
	Name string `json:"domain_name"`
	// Path to certificate file
	CertFile string `json:"cert_file"`
	// Path to private key file
	KeyFile string `json:"key_file"`
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

// Global function that will return the config of the gw running
var Global func() Config

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
	var r io.ReadCloser
	for _, filename := range paths {
		f, err := os.Open(filename)
		if err == nil {
			r = f
			defer r.Close()
			conf.OriginalPath = filename
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

	shouldOmit, omitEnvExist := os.LookupEnv(envPrefix + "_OMITCONFIGFILE")
	if omitEnvExist && strings.ToLower(shouldOmit) == "true" {
		*conf = Config{}
	}

	if err := envconfig.Process(envPrefix, conf); err != nil {
		return fmt.Errorf("failed to process config env vars: %v", err)
	}
	if err := processCustom(envPrefix, conf, loadZipkin, loadJaeger); err != nil {
		return fmt.Errorf("failed to process config custom loader: %v", err)
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

// processCustom these are custom functions for loadign config values. They will
// be called in the order they are passed. Any function that returns an error
// then that error will be returned and no further processing will be
// happenning.
func processCustom(prefix string, c *Config, custom ...func(prefix string, c *Config) error) error {
	for _, fn := range custom {
		if err := fn(prefix, c); err != nil {
			return err
		}
	}
	return nil
}

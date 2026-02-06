package config

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/otel"
	logger "github.com/TykTechnologies/tyk/log"
	"github.com/TykTechnologies/tyk/regexp"
)

type IPsHandleStrategy string

const GracefulShutdownDefaultDuration = 30

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
		HealthCheckEndpointName:    "hello",
		ReadinessCheckEndpointName: "ready",
		CoProcessOptions: CoProcessConfig{
			EnableCoProcess: false,
		},
		LivenessCheck: LivenessCheckConfig{
			CheckDuration: time.Second * 10,
		},
		GracefulShutdownTimeoutDuration: GracefulShutdownDefaultDuration,
		Streaming: StreamingConfig{
			Enabled:     false,
			AllowUnsafe: []string{},
		},
		PIDFileLocation: "/var/run/tyk/tyk-gateway.pid",
		Security: SecurityConfig{
			CertificateExpiryMonitor: CertificateExpiryMonitorConfig{
				WarningThresholdDays: DefaultWarningThresholdDays,
				CheckCooldownSeconds: DefaultCheckCooldownSeconds,
				EventCooldownSeconds: DefaultEventCooldownSeconds,
			},
		},
	}
)

// Certificate monitor constants
const (
	// DefaultWarningThresholdDays is the number of days before certificate expiration that the Gateway will start sending CertificateExpiringSoon notifications
	DefaultWarningThresholdDays = 30

	// DefaultCheckCooldownSeconds is the minimum time in seconds that the Gateway will leave between checking for the expiry of a certificate when it is used in an API request
	DefaultCheckCooldownSeconds = 3600 // 1 hour

	// DefaultEventCooldownSeconds is the minimum time in seconds that the Gateway will leave between firing an event for an expiring or expired certificate; this default will be applied as a floor value to protect the system from misconfiguration, but can be overridden by setting a longer cooldown in the CertificateExpiryMonitorConfig
	DefaultEventCooldownSeconds = 86400 // 24 hours
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

	DefaultOTelResourceName = "tyk-gateway"
)

type PolicySource string

const (
	PolicySourceService PolicySource = "service"
	PolicySourceRpc     PolicySource = "rpc"
	PolicySourceFile    PolicySource = "file"
)

type PoliciesConfig struct {
	// Set this value to `file` to look in the file system for a definition file. Set to `service` to use the Dashboard service.
	PolicySource PolicySource `json:"policy_source"`

	// This option is required if `policies.policy_source` is set to `service`.
	// Set this to the URL of your Tyk Dashboard installation. The URL needs to be formatted as: http://dashboard_host:port.
	PolicyConnectionString string `json:"policy_connection_string" structviewer:"obfuscate"`

	// This option only applies in OSS deployment when the `policies.policy_source` is either set
	// to `file` or an empty string. If `policies.policy_path` is not set, then Tyk will load policies
	// from the JSON file specified by `policies.policy_record_name`.
	PolicyRecordName string `json:"policy_record_name"`

	// In a Pro installation, Tyk will load Policy IDs and use the internal object-ID as the ID of the policy.
	// This is not portable in cases where the data needs to be moved from installation to installation.
	//
	// If you set this value to `true`, then the id parameter in a stored policy (or imported policy using the Dashboard API), will be used instead of the internal ID.
	//
	// This option should only be used when moving an installation to a new database.
	//
	// Deprecated. Is not used in codebase.
	AllowExplicitPolicyID bool `json:"allow_explicit_policy_id"`
	// This option only applies in OSS deployment when the `policies.policy_source` is either set
	// to `file` or an empty string. If `policies.policy_path` is set, then Tyk will load policies
	// from all the JSON files under the directory specified by the `policies.policy_path` option.
	// In this configuration, Tyk Gateway will allow policy management through the Gateway API.
	PolicyPath string `json:"policy_path"`
}

type DBAppConfOptionsConfig struct {
	// Set the URL to your Dashboard instance (or a load balanced instance). The URL needs to be formatted as: `http://dashboard_host:port`
	ConnectionString string `json:"connection_string" structviewer:"obfuscate"`

	// Set a timeout value, in seconds, for your Dashboard connection. Default value is 30.
	ConnectionTimeout int `json:"connection_timeout"`

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
	SentinelPassword string `json:"sentinel_password" structviewer:"obfuscate"`
	// Redis user name
	Username string `json:"username"`
	// If your Redis instance has a password set for access, you can set it here.
	Password string `json:"password" structviewer:"obfuscate"`
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
	// Path to the CA file.
	CAFile string `json:"ca_file"`
	// Path to the cert file.
	CertFile string `json:"cert_file"`
	// Path to the key file.
	KeyFile string `json:"key_file"`
	// Maximum TLS version that is supported.
	// Options: ["1.0", "1.1", "1.2", "1.3"].
	// Defaults to "1.3".
	TLSMaxVersion string `json:"tls_max_version"`
	// Minimum TLS version that is supported.
	// Options: ["1.0", "1.1", "1.2", "1.3"].
	// Defaults to "1.2".
	TLSMinVersion string `json:"tls_min_version"`
	// Enables Zstd compression of API definitions stored in Redis backups.
	// When enabled, API definitions are compressed before encryption, reducing Redis storage.
	// The Gateway can read both compressed and uncompressed formats for backward compatibility.
	// Note: Decompression has a 100MB memory limit.
	// Defaults to false.
	CompressAPIDefinitions bool `json:"compress_api_definitions"`
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

	// Set this to true to have Tyk automatically clean up ULIDs. It will match the following style:
	//
	// * `/posts/01G9HHNKWGBHCQX7VG3JKSZ055/comments`
	// * `/posts/01g9hhnkwgbhcqx7vg3jksz055/comments`
	// * `/posts/01g9HHNKwgbhcqx7vg3JKSZ055/comments`

	// Each ULID will be replaced with a placeholder {ulid}
	NormaliseULIDs bool `json:"normalise_ulids"`

	// Set this to true to have Tyk automatically match for numeric IDs, it will match with a preceding slash so as not to capture actual numbers:
	NormaliseNumbers bool `json:"normalise_numbers"`

	// This is a list of custom patterns you can add. These must be valid regex strings. Tyk will replace these values with a `{var}` placeholder.
	Custom []string `json:"custom_patterns"`

	CompiledPatternSet NormaliseURLPatterns `json:"-"` // see analytics.go
}

type NormaliseURLPatterns struct {
	UUIDs  *regexp.Regexp
	ULIDs  *regexp.Regexp
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
	// This setting can be overridden with an organization flag, enabed at an API level, or on individual Key level.
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

// AccessLogsConfig defines the type of transactions logs printed to stdout.
type AccessLogsConfig struct {
	// Enabled controls the generation of access logs by the Gateway. Default: false.
	Enabled bool `json:"enabled"`

	// Template configures which fields to include in the access log.
	// If no template is configured, all available fields will be logged.
	//
	// Example: ["client_ip", "path"].
	//
	// Template Options:
	//
	// - `api_key` will include the obfuscated or hashed key.
	// - `circuit_breaker_state` will include the circuit breaker state when applicable.
	// - `client_ip` will include the IP of the request.
	// - `error_source` will include the source of an error (e.g., ReverseProxy).
	// - `error_target` will include the target that caused an error.
	// - `host` will include the host of the request.
	// - `latency_gateway` will include the gateway processing latency.
	// - `latency_total` will include the total latency of the request.
	// - `method` will include the request method.
	// - `org_id` will include the organization ID.
	// - `path` will include the path of the request.
	// - `protocol` will include the protocol of the request.
	// - `remote_addr` will include the remote address of the request.
	// - `response_code_details` will include detailed error description for 5XX responses.
	// - `response_flag` will include the error classification flag (e.g., URT, UCF, TLE).
	// - `status` will include the response status code.
	// - `tls_cert_expiry` will include the TLS certificate expiry date when applicable.
	// - `tls_cert_subject` will include the TLS certificate subject when applicable.
	// - `trace_id` will include the OpenTelemetry trace ID when tracing is enabled.
	// - `upstream_addr` will include the upstream address (scheme, host and path).
	// - `upstream_latency` will include the upstream latency of the request.
	// - `upstream_status` will include the upstream response status code for 5XX responses.
	// - `user_agent` will include the user agent of the request.
	Template []string `json:"template"`
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
	// Frequencies of performing interval healthchecks for Redis, Dashboard, and RPC layer.
	// Expressed in Nanoseconds. For example: 1000000000 -> 1s.
	// Default: 10 seconds.
	CheckDuration time.Duration `json:"check_duration"`
}

type DnsCacheConfig struct {
	// Setting this value to `true` will enable caching of DNS queries responses used for API endpoint’s host names. By default caching is disabled.
	Enabled bool `json:"enabled"`

	// This setting allows you to specify a duration in seconds before the record will be removed from cache after being added to it on the first DNS query resolution of API endpoints.
	// Setting `ttl` to `-1` prevents record from being expired and removed from cache on next check interval.
	TTL int64 `json:"ttl"`

	CheckInterval int64 `json:"-" ignored:"true"`
	// controls cache cleanup interval. By convention this shouldn't be exposed to a config or env_variable_setup

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
	// Apply the monitoring subsystem to organization keys.
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

// DNSMonitorConfig configures the background DNS monitoring for worker gateways
type DNSMonitorConfig struct {
	// Enable background DNS monitoring for proactive detection of MDCB DNS changes
	Enabled bool `json:"enabled"`
	// Check interval in seconds for DNS monitoring (default: 30)
	CheckInterval int `json:"check_interval"`
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
	ConnectionString string `json:"connection_string" structviewer:"obfuscate"`

	// Your organization ID to connect to the MDCB installation.
	RPCKey string `json:"rpc_key"`

	// This the API key of a user used to authenticate and authorize the Gateway's access through MDCB.
	// The user should be a standard Dashboard user with minimal privileges so as to reduce any risk if the user is compromised.
	// The suggested security settings are read for Real-time notifications and the remaining options set to deny.
	APIKey string `json:"api_key" structviewer:"obfuscate"`

	// Set this option to `true` to enable RPC caching for keys.
	EnableRPCCache bool `json:"enable_rpc_cache"`

	// For an Self-Managed installation this can be left at `false` (the default setting). For Legacy Cloud Gateways it must be set to ‘true’.
	BindToSlugsInsteadOfListenPaths bool `json:"bind_to_slugs"`

	// Set this option to `true` if you don’t want to monitor changes in the keys from a primary Gateway.
	DisableKeySpaceSync bool `json:"disable_keyspace_sync"`

	// This is the `zone` that this instance inhabits, e.g. the cluster/data-center the Gateway lives in.
	// The group ID must be the same across all the Gateways of a data-center/cluster which are also sharing the same Redis instance.
	// This ID should also be unique per cluster (otherwise another Gateway cluster can pick up your keyspace events and your cluster will get zero updates).
	GroupID string `json:"group_id"`

	// Call Timeout allows to specify a time in seconds for the maximum allowed duration of a RPC call.
	CallTimeout int `json:"call_timeout"`

	// The maximum time in seconds that a RPC ping can last.
	PingTimeout int `json:"ping_timeout"`

	// The number of RPC connections in the pool. Basically it creates a set of connections that you can re-use as needed. Defaults to 5.
	RPCPoolSize int `json:"rpc_pool_size"`

	// You can use this to set a period for which the Gateway will check if there are changes in keys that must be synchronized. If this value is not set then it will default to 10 seconds.
	KeySpaceSyncInterval float32 `json:"key_space_sync_interval"`

	// RPCCertCacheExpiration defines the expiration time of the rpc cache that stores the certificates, defined in seconds
	RPCCertCacheExpiration float32 `json:"rpc_cert_cache_expiration"`

	// RPCKeysCacheExpiration defines the expiration time of the rpc cache that stores the keys, defined in seconds
	RPCGlobalCacheExpiration float32 `json:"rpc_global_cache_expiration"`

	// SynchroniserEnabled enable this config if MDCB has enabled the synchoniser. If disabled then it will ignore signals to synchonise recources
	SynchroniserEnabled bool `json:"synchroniser_enabled"`

	// DNSMonitor configures background DNS monitoring for proactive detection of MDCB DNS changes
	DNSMonitor DNSMonitorConfig `json:"dns_monitor"`

	// Set to true to sync only certificates used by loaded APIs.
	// Only applies when use_rpc is true.
	// Prevents proactive sync of unused certificates from control plane.
	// Certificates are fetched on-demand via RPC and cached locally.
	// Note: Certificates accumulate over time as they are used; they are not removed when APIs are deleted.
	// Reduces memory usage and log noise in segmented deployments.
	SyncUsedCertsOnly bool `json:"sync_used_certs_only"`
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
	//
	// Note:
	//   If you set `proxy_default_timeout` to a value greater than 120 seconds, you must also increase [http_server_options.write_timeout](#http-server-options-write-timeout) to a value greater than `proxy_default_timeout`. The `write_timeout` setting defaults to 120 seconds and controls how long Tyk waits to write the response back to the client. If not adjusted, the client connection will be closed before the upstream response is received.
	WriteTimeout int `json:"write_timeout"`

	// Set to true to enable SSL connections
	UseSSL bool `json:"use_ssl"`

	// Enable HTTP2 protocol handling
	EnableHttp2 bool `json:"enable_http2"`

	// EnableStrictRoutes changes the routing to avoid nearest-neighbour requests on overlapping routes
	//
	// - if disabled, `/apple` will route to `/app`, the current default behavior,
	// - if enabled, `/app` only responds to `/app`, `/app/` and `/app/*` but not `/apple`
	//
	// Regular expressions and parameterized routes will be left alone regardless of this setting.
	EnableStrictRoutes bool `json:"enable_strict_routes"`

	// EnablePathPrefixMatching changes how the gateway matches incoming URL paths against routes (patterns) defined in the API definition.
	// By default, the gateway uses wildcard matching. When EnablePathPrefixMatching is enabled, it switches to prefix matching. For example, a defined path such as `/json` will only match request URLs that begin with `/json`, rather than matching any URL containing `/json`.
	//
	// The gateway checks the request URL against several variations depending on whether path versioning is enabled:
	// - Full path (listen path + version + endpoint): `/listen-path/v4/json`
	// - Non-versioned full path (listen path + endpoint): `/listen-path/json`
	// - Path without version (endpoint only): `/json`
	//
	// For patterns that start with `/`, the gateway prepends `^` before performing the check, ensuring a true prefix match.
	// For patterns that start with `^`, the gateway will already perform prefix matching so EnablePathPrefixMatching will have no impact.
	// This option allows for more specific and controlled routing of API requests, potentially reducing unintended matches. Note that you may need to adjust existing route definitions when enabling this option.
	//
	// Example:
	//
	// With wildcard matching, `/json` might match `/api/v1/data/json`.
	// With prefix matching, `/json` would not match `/api/v1/data/json`, but would match `/json/data`.
	//
	// Combining EnablePathPrefixMatching with EnablePathSuffixMatching will result in exact URL matching, with `/json` being evaluated as `^/json$`.
	EnablePathPrefixMatching bool `json:"enable_path_prefix_matching"`

	// EnablePathSuffixMatching changes how the gateway matches incoming URL paths against routes (patterns) defined in the API definition.
	// By default, the gateway uses wildcard matching. When EnablePathSuffixMatching is enabled, it switches to suffix matching. For example, a defined path such as `/json` will only match request URLs that end with `/json`, rather than matching any URL containing `/json`.
	//
	// The gateway checks the request URL against several variations depending on whether path versioning is enabled:
	// - Full path (listen path + version + endpoint): `/listen-path/v4/json`
	// - Non-versioned full path (listen path + endpoint): `/listen-path/json`
	// - Path without version (endpoint only): `/json`
	//
	// For patterns that already end with `$`, the gateway will already perform suffix matching so EnablePathSuffixMatching will have no impact. For all other patterns, the gateway appends `$` before performing the check, ensuring a true suffix match.
	// This option allows for more specific and controlled routing of API requests, potentially reducing unintended matches. Note that you may need to adjust existing route definitions when enabling this option.
	//
	// Example:
	//
	// With wildcard matching, `/json` might match `/api/v1/json/data`.
	// With suffix matching, `/json` would not match `/api/v1/json/data`, but would match `/api/v1/json`.
	//
	// Combining EnablePathSuffixMatching with EnablePathPrefixMatching will result in exact URL matching, with `/json` being evaluated as `^/json$`.
	EnablePathSuffixMatching bool `json:"enable_path_suffix_matching"`

	// Disable TLS verification. Required if you are using self-signed certificates.
	SSLInsecureSkipVerify bool `json:"ssl_insecure_skip_verify"`

	// Enabled WebSockets and server side events support
	EnableWebSockets bool `json:"enable_websockets"`

	// Deprecated: Use `ssl_certificates`instead.
	Certificates CertsData `json:"certificates"`

	// Index of certificates available to the Gateway for use in client and upstream communication.
	// The string value in the array can be two of the following options:
	// 1. The ID assigned to and used to identify a certificate in the Tyk Certificate Store
	// 2. The path to a file accessible to the Gateway. This PEM file must contain the private key and public certificate pair concatenated together.
	SSLCertificates []string `json:"ssl_certificates"`

	// Start your Gateway HTTP server on specific server name
	ServerName string `json:"server_name"`

	// Minimum TLS version. Possible values: https://tyk.io/docs/api-management/certificates#supported-tls-versions
	MinVersion uint16 `json:"min_version"`

	// Maximum TLS version.
	MaxVersion uint16 `json:"max_version"`

	// When mTLS enabled, this option allows to skip client CA announcement in the TLS handshake.
	// This option is useful when you have a lot of ClientCAs and you want to reduce the handshake overhead, as some clients can hit TLS handshake limits.
	// This option does not give any hints to the client, on which certificate to pick (but this is very rare situation when it is required)
	SkipClientCAAnnouncement bool `json:"skip_client_ca_announcement"`

	// Set this to the number of seconds that Tyk uses to flush content from the proxied upstream connection to the open downstream connection.
	// This option needed be set for streaming protocols like Server Side Events, or gRPC streaming.
	FlushInterval int `json:"flush_interval"`

	// Allow the use of a double slash in a URL path. This can be useful if you need to pass raw URLs to your API endpoints.
	// For example: `http://myapi.com/get/http://example.com`.
	SkipURLCleaning bool `json:"skip_url_cleaning"`

	// Disable automatic character escaping, allowing to path original URL data to the upstream.
	SkipTargetPathEscaping bool `json:"skip_target_path_escaping"`

	// Custom SSL ciphers applicable when using TLS version 1.2. See the list of ciphers here https://tyk.io/docs/api-management/certificates#supported-tls-cipher-suites
	Ciphers []string `json:"ssl_ciphers"`

	// MaxRequestBodySize configures a maximum size limit for request body size (in bytes) for all APIs on the Gateway.
	//
	// Tyk Gateway will evaluate all API requests against this size limit and will respond with HTTP 413 status code if the body of the request is larger.
	//
	// Two methods are used to perform the comparison:
	//  - If the API Request contains the `Content-Length` header, this is directly compared against `MaxRequestBodySize`.
	//  - If the `Content-Length` header is not provided, the Request body is read in chunks to compare total size against `MaxRequestBodySize`.
	//
	// A value of zero (default) means that no maximum is set and API requests will not be tested.
	//
	// See more information about setting request size limits here:
	// https://tyk.io/docs/api-management/traffic-transformation/#request-size-limits
	MaxRequestBodySize int64 `json:"max_request_body_size"`

	// XFFDepth controls which position in the X-Forwarded-For chain to use for determining client IP address.
	// A value of 0 means using the first IP (default). this is way the Gateway has calculated the client IP historically,
	// the most common case, and will be used when this config is not set.
	// However, any non-zero value will use that position from the right in the X-Forwarded-For chain.
	// This is a security feature to prevent against IP spoofing attacks, and is recommended to be set to a non-zero value.
	// A value of 1 means using the last IP, 2 means second to last, and so on.
	XFFDepth int `json:"xff_depth"`

	// MaxResponseBodySize sets an upper limit on the response body (payload) size in bytes. It defaults to 0, which means there is no restriction on the response body size.
	//
	// The Gateway will return `HTTP 500 Response Body Too Large` if the response payload exceeds MaxResponseBodySize+1 bytes.
	//
	// **Note:** The limit is applied only when the [Response Body Transform middleware](/api-management/traffic-transformation/response-body) is enabled.
	MaxResponseBodySize int64 `json:"max_response_body_size"`
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

	// Authority used in GRPC connection
	GRPCAuthority string `json:"grpc_authority"`

	// GRPCRoundRobinLoadBalancing enables round robin load balancing for gRPC services; you must provide the address of the load balanced service using `dns:///` protocol in `coprocess_grpc_server`.
	GRPCRoundRobinLoadBalancing bool `json:"grpc_round_robin_load_balancing"`

	// Sets the path to built-in Tyk modules. This will be part of the Python module lookup path. The value used here is the default one for most installations.
	PythonPathPrefix string `json:"python_path_prefix"`

	// If you have multiple Python versions installed you can specify your version.
	PythonVersion string `json:"python_version"`
}

type CertificatesConfig struct {
	API []string `json:"apis"`
	// Upstream is used to specify the certificates to be used in mutual TLS connections to upstream services. These are set at gateway level as a map of domain -> certificate id or path.
	// For example if you want Tyk to use the certificate `ab23ef123` for requests to the `example.com` upstream and `/certs/default.pem` for all other upstreams then:
	// In `tyk.conf` you would configure `"security": {"certificates": {"upstream": {"*": "/certs/default.pem", "example.com": "ab23ef123"}}}`
	// And if using environment variables you would set this to `*:/certs/default.pem,example.com:ab23ef123`.
	Upstream map[string]string `json:"upstream"`
	// Certificates used for Control API Mutual TLS
	ControlAPI []string `json:"control_api"`
	// Used for communicating with the Dashboard if it is configured to use Mutual TLS
	Dashboard []string `json:"dashboard_api"`
	// Certificates used for MDCB Mutual TLS
	MDCB []string `json:"mdcb_api"`
}

// CertificateExpiryMonitorConfig configures the certificate expiration notification feature
type CertificateExpiryMonitorConfig struct {
	// WarningThresholdDays specifies the number of days before certificate expiry that the Gateway will start generating CertificateExpiringSoon events when the certificate is used
	// Default: DefaultWarningThresholdDays (30 days)
	WarningThresholdDays int `json:"warning_threshold_days"`

	// CheckCooldownSeconds specifies the minimum time in seconds that the Gateway will leave between checking for the expiry of a certificate when it is used in an API request - if a certificate is used repeatedly this prevents unnecessary expiry checks
	// Default: DefaultCheckCooldownSeconds (3600 seconds = 1 hour)
	CheckCooldownSeconds int `json:"check_cooldown_seconds"`

	// EventCooldownSeconds specifies the minimum time in seconds between firing the same certificate expiry event - this prevents unnecessary events from being generated for an expiring or expired certificate being used repeatedly; note that the higher of the value configured here or the default (DefaultEventCooldownSeconds) will be applied
	// Default: DefaultEventCooldownSeconds (86400 seconds = 24 hours)
	EventCooldownSeconds int `json:"event_cooldown_seconds"`
}

type SecurityConfig struct {
	// Set the AES256 secret which is used to encode certificate private keys when they uploaded via certificate storage
	PrivateCertificateEncodingSecret string `json:"private_certificate_encoding_secret" structviewer:"obfuscate"`

	// Enable Gateway Control API to use Mutual TLS. Certificates can be set via `security.certificates.control_api` section
	ControlAPIUseMutualTLS bool `json:"control_api_use_mutual_tls"`

	// Specify public keys used for Certificate Pinning on global level.
	PinnedPublicKeys map[string]string `json:"pinned_public_keys"`

	// AllowUnsafeDynamicMTLSToken controls whether certificate presence is required for
	// dynamic mTLS authentication. If set to false (default), requests with a token but
	// no certificate will be rejected for APIs using dynamic mTLS.
	AllowUnsafeDynamicMTLSToken bool `json:"allow_unsafe_dynamic_mtls_token"`

	Certificates CertificatesConfig `json:"certificates"`

	// CertificateExpiryMonitor configures the certificate expiry monitoring and notification feature
	CertificateExpiryMonitor CertificateExpiryMonitorConfig `json:"certificate_expiry_monitor"`
}

type JWKSConfig struct {
	// Cache hodls configuration for JWKS caching
	Cache JWKSCacheConfig `json:"cache"`
}

type JWKSCacheConfig struct {
	// Timeout defines how long the JWKS will be kept in the cache before forcing a refresh from the JWKS endpoint.
	// Default is 240 seconds (4 minutes). Set to 0 to use the default value.
	Timeout int64 `json:"timeout"`
}

type NewRelicConfig struct {
	// New Relic Application name
	AppName string `json:"app_name"`
	// New Relic License key
	LicenseKey string `json:"license_key" structviewer:"obfuscate"`
	// Enable distributed tracing
	EnableDistributedTracing bool `json:"enable_distributed_tracing"`
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

// StreamingConfig holds the configuration for Tyk Streaming functionalities
type StreamingConfig struct {
	// This flag enables the Tyk Streaming feature.
	Enabled bool `json:"enabled"`
	// AllowUnsafe specifies a list of potentially unsafe streaming components that should be allowed in the configuration.
	// By default, components that could pose security risks (like file access, subprocess execution, socket operations, etc.)
	// are filtered out. This field allows administrators to explicitly permit specific unsafe components when needed.
	// Use with caution as enabling unsafe components may introduce security vulnerabilities.
	AllowUnsafe []string `json:"allow_unsafe"`
}

// Config is the configuration object used by Tyk to set up various parameters.
type Config struct {
	// Force your Gateway to work only on a specific domain name. Can be overridden by API custom domain.
	HostName string `json:"hostname"`

	// If your machine has multiple network devices or IPs you can force the Gateway to use the IP address you want.
	ListenAddress string `json:"listen_address"`

	// Setting this value will change the port that Tyk listens on. Default: 8080.
	ListenPort int `json:"listen_port"`

	// Custom hostname for the Control API
	ControlAPIHostname string `json:"control_api_hostname"`

	// Set this to expose the Tyk Gateway API on a separate port. You can protect it behind a firewall if needed. Please make sure you follow this guide when setting the control port https://tyk.io/docs/tyk-self-managed/#change-your-control-port.
	ControlAPIPort int `json:"control_api_port"`

	// This should be changed as soon as Tyk is installed on your system.
	// This value is used in every interaction with the Tyk Gateway API. It should be passed along as the X-Tyk-Authorization header in any requests made.
	// Tyk assumes that you are sensible enough not to expose the management endpoints publicly and to keep this configuration value to yourself.
	Secret string `json:"secret" structviewer:"obfuscate"`

	// The shared secret between the Gateway and the Dashboard to ensure that API Definition downloads, heartbeat and Policy loads are from a valid source.
	NodeSecret string `json:"node_secret" structviewer:"obfuscate"`

	// Linux PID file location. Do not change unless you know what you are doing. Default: /var/run/tyk/tyk-gateway.pid
	PIDFileLocation string `json:"pid_file_location"`

	// Can be set to disable Dashboard message signature verification. When set to `true`, `public_key_path` can be ignored.
	AllowInsecureConfigs bool `json:"allow_insecure_configs"`

	// While communicating with the Dashboard. By default, all messages are signed by a private/public key pair. Set path to public key.
	PublicKeyPath string `json:"public_key_path"`

	// Allow your Dashboard to remotely set Gateway configuration via the Nodes screen.
	AllowRemoteConfig bool `bson:"allow_remote_config" json:"allow_remote_config"`

	// Set to true to enable the /config and /env endpoints for configuration inspection.
	// These endpoints require X-Tyk-Authorization header with the secret value.
	// Default: false
	EnableConfigInspection bool `json:"enable_config_inspection"`

	// Global Certificate configuration
	Security SecurityConfig `json:"security"`

	// External service configuration for proxy and mTLS support
	ExternalServices ExternalServiceConfig `json:"external_services"`

	// Gateway HTTP server configuration
	HttpServerOptions HttpServerOptionsConfig `json:"http_server_options"`

	// Expose version header with a given name. Works only for versioned APIs.
	VersionHeader string `json:"version_header"`

	// Disable dynamic API and Policy reloads, e.g. it will load new changes only on procecss start.
	SuppressRedisSignalReload bool `json:"suppress_redis_signal_reload"`

	// ReloadInterval defines a duration in seconds within which the gateway responds to a reload event.
	// The value defaults to 1, values lower than 1 are ignored.
	ReloadInterval int64 `json:"reload_interval"`

	// Enable Key hashing
	HashKeys bool `json:"hash_keys"`

	// DisableKeyActionsByUsername disables key search by username.
	// When this is set to `true` you are able to search for keys only by keyID or key hash (if `hash_keys` is also set to `true`)
	// Note that if `hash_keys` is also set to `true` then the keyID will not be provided for APIs secured using basic auth. In this scenario the only search option would be to use key hash
	// If you are using the Tyk Dashboard, you must configure this setting with the same value in both Gateway and Dashboard
	DisableKeyActionsByUsername bool `json:"disable_key_actions_by_username"`

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

	// Defines the ports that will be available for the API services to bind to in the format
	// documented here https://tyk.io/docs/api-management/non-http-protocols/#allowing-specific-ports.
	// Ports can be configured per protocol, e.g. https, tls etc.
	// If configuring via environment variable `TYK_GW_PORTWHITELIST` then remember to escape
	// JSON strings.
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
	// In some specific cases, for example, when the Dashboard is bound to a public domain, not accessible inside an internal network, or similar, `disable_dashboard_zeroconf` can be set to `true`, in favor of directly specifying a Tyk Dashboard address.
	DisableDashboardZeroConf bool `json:"disable_dashboard_zeroconf"`

	// The `slave_options` allow you to configure the RPC slave connection required for MDCB installations.
	// These settings must be configured for every RPC slave/worker node.
	SlaveOptions SlaveOptionsConfig `json:"slave_options"`

	// If set to `true`, distributed rate limiter will be disabled for this node, and it will be excluded from any rate limit calculation.
	//
	// Note:
	//   If you set `db_app_conf_options.node_is_segmented` to `true` for multiple Gateway nodes, you should ensure that `management_node` is set to `false`.
	//   This is to ensure visibility for the management node across all APIs.
	//
	//   For pro installations, `management_node` is not a valid configuration option.
	//   Always set `management_node` to `false` in pro environments.
	ManagementNode bool `json:"management_node"`

	// This is used as part of the RPC / Hybrid back-end configuration in a Tyk Enterprise installation and isn’t used anywhere else.
	AuthOverride AuthOverrideConf `json:"auth_override"`

	// RateLimit encapsulates rate limit configuration definitions.
	RateLimit

	// Allows you to dynamically configure analytics expiration on a per organization level
	EnforceOrgDataAge bool `json:"enforce_org_data_age"`

	// Allows you to dynamically configure detailed logging on a per organization level
	EnforceOrgDataDetailLogging bool `json:"enforce_org_data_detail_logging"`

	// Allows you to dynamically configure organization quotas on a per organization level
	EnforceOrgQuotas bool `json:"enforce_org_quotas"`

	ExperimentalProcessOrgOffThread bool `json:"experimental_process_org_off_thread"`

	// The monitor section is useful if you wish to enforce a global trigger limit on organization and user quotas.
	// This feature will trigger a webhook event to fire when specific triggers are reached.
	// Triggers can be global (set in the node), by organization (set in the organization session object) or by key (set in the key session object)
	//
	// While Organization-level and Key-level triggers can be tiered (e.g. trigger at 10%, trigger at 20%, trigger at 80%), in the node-level configuration only a global value can be set.
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
	// Maximum idle connections, per API, per upstream, between Tyk and Upstream.
	// A value of `0` will use the default from the Go standard library, which is 2 connections. Tyk recommends setting this value to `500` for production environments.
	MaxIdleConnsPerHost int `bson:"max_idle_connections_per_host" json:"max_idle_connections_per_host"`
	// Maximum connection time. If set it will force gateway reconnect to the upstream.
	MaxConnTime int64 `json:"max_conn_time"`

	// If set, disable keepalive between User and Tyk
	CloseConnections bool `json:"close_connections"`

	// Allows you to use custom domains
	EnableCustomDomains bool `json:"enable_custom_domains"`

	// If AllowMasterKeys is set to true, session objects (key definitions) that do not have explicit access rights set
	// will be allowed by Tyk. This means that keys that are created have access to ALL APIs, which in many cases is
	// unwanted behavior unless you are sure about what you are doing.
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

	// Allow list of ciphers for connection between Tyk and your upstream service.
	ProxySSLCipherSuites []string `json:"proxy_ssl_ciphers"`

	// This can specify a default timeout in seconds for upstream API requests.
	// Default: 30 seconds
	//
	// Note:
	//   If you set `proxy_default_timeout` to a value greater than 120 seconds, you must also increase [http_server_options.write_timeout](#http-server-options-write-timeout) to a value greater than `proxy_default_timeout`. The `write_timeout` setting defaults to 120 seconds and controls how long Tyk waits to write the response back to the client. If not adjusted, the client connection will be closed before the upstream response is received.
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

	// HealthCheckEndpointName Enables you to change the liveness endpoint.
	// Default is "/hello"
	HealthCheckEndpointName string `json:"health_check_endpoint_name"`

	// ReadinessCheckEndpointName Enables you to change the readiness endpoint
	// Default is "/ready"
	ReadinessCheckEndpointName string `json:"readiness_check_endpoint_name"`

	// GracefulShutdownTimeoutDuration sets how many seconds the gateway should wait for an existing connection
	//to finish before shutting down the server. Defaults to 30 seconds.
	GracefulShutdownTimeoutDuration int `json:"graceful_shutdown_timeout_duration"`

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

	// SkipVerifyExistingPluginBundle skips checksum verification for plugin bundles already on disk.
	SkipVerifyExistingPluginBundle bool `bson:"skip_verify_existing_plugin_bundle" json:"skip_verify_existing_plugin_bundle"`

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

	// You can now configure the log format to be either the standard or json format
	// If not set or left empty, it will default to `standard`.
	LogFormat string `json:"log_format"`

	// AccessLogs configures the output for access logs.
	// If not configured, the access log is disabled.
	AccessLogs AccessLogsConfig `json:"access_logs"`

	// Section for configuring OpenTracing support
	// Deprecated: use OpenTelemetry instead.
	Tracer Tracer `json:"tracing"`

	// Section for configuring OpenTelemetry.
	OpenTelemetry otel.OpenTelemetry `json:"opentelemetry"`

	NewRelic NewRelicConfig `json:"newrelic"`

	// Enable debugging of your Tyk Gateway by exposing profiling information through https://tyk.io/docs/api-management/troubleshooting-debugging
	HTTPProfile bool `json:"enable_http_profiler"`

	// Enables the real-time Gateway log view in the Dashboard.
	//
	// Note:
	//   For logs to appear in the Tyk Dashboard, both the Gateway and the Dashboard must be configured to use the **same Redis instance**.
	//   In deployments where the Data Plane (Gateway) and Control Plane (Dashboard) use separate Redis instances,
	//   enabling this option on the Gateway will not make logs available in the Dashboard.
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
	// See more details https://tyk.io/docs/tyk-self-managed/#store-configuration-with-key-value-store
	KV struct {
		Consul ConsulConfig `json:"consul"`
		Vault  VaultConfig  `json:"vault"`
	} `json:"kv"`

	// Secrets configures a list of key/value pairs for the gateway.
	// When configuring it via environment variable, the expected value
	// is a comma separated list of key-value pairs delimited with a colon.
	//
	// Example: `TYK_GW_SECRETS=key1:value1,key2:/value2`
	// Produces: `{"key1": "value1", "key2": "/value2"}`
	//
	// The secret value may be used as `secrets://key1` from the API definition.
	// In versions before gateway 5.3, only `listen_path` and `target_url` fields
	// have had the secrets replaced.
	// See more details https://tyk.io/docs/tyk-self-managed/#how-to-access-the-externally-stored-data
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
	//    "message": "Token is not authorized"
	//  }
	// }
	// ```
	OverrideMessages map[string]TykError `bson:"override_messages" json:"override_messages"`

	// Cloud flag shows the Gateway runs in Tyk Cloud.
	Cloud bool `json:"cloud"`

	// Skip TLS verification for JWT JWKs url validation
	JWTSSLInsecureSkipVerify bool `json:"jwt_ssl_insecure_skip_verify"`

	// ResourceSync configures mitigation strategy in case sync fails.
	ResourceSync ResourceSyncConfig `json:"resource_sync"`

	// Private contains configuration fields for internal app usage.
	Private Private `json:"-"`

	// DevelopmentConfig struct extends configuration for development builds.
	DevelopmentConfig

	// OAS holds the configuration for various OpenAPI-specific functionalities
	OAS OASConfig `json:"oas_config"`

	// Streaming holds the configuration for Tyk Streaming functionalities
	Streaming StreamingConfig `json:"streaming"`

	Labs LabsConfig `json:"labs"`

	// JWKS holds the configuration for Tyk JWKS functionalities
	JWKS JWKSConfig `json:"jwks"`
}

// LabsConfig include config for streaming
type LabsConfig map[string]interface{}

// Decode unmarshals json config into the Labs config
func (lc *LabsConfig) Decode(value string) error {
	var temp map[string]interface{}
	if err := json.Unmarshal([]byte(value), &temp); err != nil {
		log.Error("Error unmarshalling LabsConfig: ", err)
		return err
	}
	*lc = temp
	return nil
}

// OASConfig holds the configuration for various OpenAPI-specific functionalities
type OASConfig struct {
	// ValidateExamples enables validation of values provided in `example` and `examples` fields against the declared schemas in the OpenAPI Document. Defaults to false.
	ValidateExamples bool `json:"validate_examples"`

	// ValidateSchemaDefaults enables validation of values provided in `default` fields against the declared schemas in the OpenAPI Document. Defaults to false.
	ValidateSchemaDefaults bool `json:"validate_schema_defaults"`
}

type ResourceSyncConfig struct {
	// RetryAttempts defines the number of retries that the Gateway
	// should perform during a resource sync (APIs or policies), defaulting
	// to zero which means no retries are attempted.
	RetryAttempts int `json:"retry_attempts"`

	// Interval configures the interval in seconds between each retry on a resource sync error.
	Interval int `json:"interval"`
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
	Token string `json:"token" structviewer:"obfuscate"`

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
		Password string `json:"password" structviewer:"obfuscate"`
	} `json:"http_auth"`

	// WaitTime limits how long a Watch will block. If not provided,
	// the agent default values will be used.
	WaitTime time.Duration `json:"wait_time"`

	// Token is used to provide a per-request ACL token
	// which overrides the agent's default token.
	Token string `json:"token" structviewer:"obfuscate"`

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

// SetEventTriggers sets events for backwards compatibility
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
func WriteDefault(in string, conf *Config) error {
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("Can't get working directory: %w", err)
	}

	*conf = Default
	conf.TemplatePath = filepath.Join(wd, "templates")
	if err := envconfig.Process(envPrefix, conf); err != nil {
		return err
	}
	if in == "" {
		return nil
	}
	return WriteConf(in, conf)
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
			conf.Private.OriginalPath = filename
			break
		}
		if os.IsNotExist(err) {
			continue
		}
		return err
	}

	if len(paths) > 0 && r == nil {
		filename := paths[0]
		log.Warnf("No config file found, writing default to %s", filename)
		if err := WriteDefault(filename, conf); err != nil {
			return err
		}
		log.Info("Loading default configuration...")
		return Load([]string{filename}, conf)
	}

	if r != nil {
		if err := json.NewDecoder(r).Decode(&conf); err != nil {
			return fmt.Errorf("couldn't unmarshal config: %w", err)
		}
	}

	if err := FillEnv(conf); err != nil {
		log.WithError(err).Error("Failed to process environment variables after config file load")
		return err
	}

	return nil
}

// FillEnv will inspect the environment and fill the config.
func FillEnv(conf *Config) error {
	shouldOmit, omitEnvExist := os.LookupEnv(envPrefix + "_OMITCONFIGFILE")
	if omitEnvExist && strings.ToLower(shouldOmit) == "true" {
		*conf = Config{}
	}

	if err := envconfig.Process(envPrefix, conf); err != nil {
		return fmt.Errorf("failed to process config env vars: %w", err)
	}
	if err := processCustom(envPrefix, conf, loadZipkin, loadJaeger); err != nil {
		return fmt.Errorf("failed to process config custom loader: %w", err)
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

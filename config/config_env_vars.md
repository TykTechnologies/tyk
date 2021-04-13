This application is configured via the environment. The following environment
variables can be used:

key | json | type 
----|------|----
TYK_GW_HOSTNAME | hostname |String
TYK_GW_LISTENADDRESS | listen_address |String
TYK_GW_LISTENPORT | listen_port |Integer
TYK_GW_CONTROLAPIHOSTNAME | control_api_hostname |String
TYK_GW_CONTROLAPIPORT | control_api_port |Integer
TYK_GW_SECRET | secret |String
TYK_GW_NODESECRET | node_secret |String
TYK_GW_PIDFILELOCATION | pid_file_location |String
TYK_GW_ALLOWINSECURECONFIGS | allow_insecure_configs |True or False
TYK_GW_PUBLICKEYPATH | public_key_path |String
TYK_GW_ALLOWREMOTECONFIG | allow_remote_config |True or False
TYK_GW_SECURITY_PRIVATECERTIFICATEENCODINGSECRET | private_certificate_encoding_secret |String
TYK_GW_SECURITY_CONTROLAPIUSEMUTUALTLS | control_api_use_mutual_tls |True or False
TYK_GW_SECURITY_PINNEDPUBLICKEYS | pinned_public_keys |Comma-separated list of String:String pairs
TYK_GW_SECURITY_CERTIFICATES_API | apis |Comma-separated list of String
TYK_GW_SECURITY_CERTIFICATES_UPSTREAM | upstream |Comma-separated list of String:String pairs
TYK_GW_SECURITY_CERTIFICATES_CONTROLAPI | control_api |Comma-separated list of String
TYK_GW_SECURITY_CERTIFICATES_DASHBOARD | dashboard_api |Comma-separated list of String
TYK_GW_SECURITY_CERTIFICATES_MDCB | mdcb_api |Comma-separated list of String
TYK_GW_HTTPSERVEROPTIONS_OVERRIDEDEFAULTS | override_defaults |True or False
TYK_GW_HTTPSERVEROPTIONS_READTIMEOUT | read_timeout |Integer
TYK_GW_HTTPSERVEROPTIONS_WRITETIMEOUT | write_timeout |Integer
TYK_GW_HTTPSERVEROPTIONS_USESSL | use_ssl |True or False
TYK_GW_HTTPSERVEROPTIONS_USELE_SSL | use_ssl_le |True or False
TYK_GW_HTTPSERVEROPTIONS_ENABLEHTTP2 | enable_http2 |True or False
TYK_GW_HTTPSERVEROPTIONS_SSLINSECURESKIPVERIFY | ssl_insecure_skip_verify |True or False
TYK_GW_HTTPSERVEROPTIONS_ENABLEWEBSOCKETS | enable_websockets |True or False
TYK_GW_HTTPSERVEROPTIONS_CERTIFICATES | certificates |Comma-separated list of 
TYK_GW_HTTPSERVEROPTIONS_SSLCERTIFICATES | ssl_certificates |Comma-separated list of String
TYK_GW_HTTPSERVEROPTIONS_SERVERNAME | server_name |String
TYK_GW_HTTPSERVEROPTIONS_MINVERSION | min_version |Unsigned Integer
TYK_GW_HTTPSERVEROPTIONS_FLUSHINTERVAL | flush_interval |Integer
TYK_GW_HTTPSERVEROPTIONS_SKIPURLCLEANING | skip_url_cleaning |True or False
TYK_GW_HTTPSERVEROPTIONS_SKIPTARGETPATHESCAPING | skip_target_path_escaping |True or False
TYK_GW_HTTPSERVEROPTIONS_CIPHERS | ssl_ciphers |Comma-separated list of String
TYK_GW_RELOADWAITTIME | reload_wait_time |Integer
TYK_GW_VERSIONHEADER | version_header |String
TYK_GW_USEASYNCSESSIONWRITE | optimisations_use_async_session_write |True or False
TYK_GW_SUPPRESSREDISSIGNALRELOAD | suppress_redis_signal_reload |True or False
TYK_GW_HASHKEYS | hash_keys |True or False
TYK_GW_HASHKEYFUNCTION | hash_key_function |String
TYK_GW_ENABLEHASHEDKEYSLISTING | enable_hashed_keys_listing |True or False
TYK_GW_MINTOKENLENGTH | min_token_length |Integer
TYK_GW_ENABLEAPISEGREGATION | enable_api_segregation |True or False
TYK_GW_TEMPLATEPATH | template_path |String
TYK_GW_POLICIES_POLICYSOURCE | policy_source |String
TYK_GW_POLICIES_POLICYCONNECTIONSTRING | policy_connection_string |String
TYK_GW_POLICIES_POLICYRECORDNAME | policy_record_name |String
TYK_GW_POLICIES_ALLOWEXPLICITPOLICYID | allow_explicit_policy_id |True or False
TYK_GW_DISABLEPORTWHITELIST | disable_ports_whitelist |True or False
TYK_GW_PORTWHITELIST | ports_whitelist |Comma-separated list of String: pairs
TYK_GW_APPPATH | app_path |String
TYK_GW_USEDBAPPCONFIGS | use_db_app_configs |True or False
TYK_GW_DBAPPCONFOPTIONS_CONNECTIONSTRING | connection_string |String
TYK_GW_DBAPPCONFOPTIONS_NODEISSEGMENTED | node_is_segmented |True or False
TYK_GW_DBAPPCONFOPTIONS_TAGS | tags |Comma-separated list of String
TYK_GW_STORAGE_TYPE | type |String
TYK_GW_STORAGE_HOST | host |String
TYK_GW_STORAGE_PORT | port |Integer
TYK_GW_STORAGE_HOSTS | hosts |Comma-separated list of String:String pairs
TYK_GW_STORAGE_ADDRS | addrs |Comma-separated list of String
TYK_GW_STORAGE_MASTERNAME | master_name |String
TYK_GW_STORAGE_USERNAME | username |String
TYK_GW_STORAGE_PASSWORD | password |String
TYK_GW_STORAGE_DATABASE | database |Integer
TYK_GW_STORAGE_MAXIDLE | optimisation_max_idle |Integer
TYK_GW_STORAGE_MAXACTIVE | optimisation_max_active |Integer
TYK_GW_STORAGE_TIMEOUT | timeout |Integer
TYK_GW_STORAGE_ENABLECLUSTER | enable_cluster |True or False
TYK_GW_STORAGE_USESSL | use_ssl |True or False
TYK_GW_STORAGE_SSLINSECURESKIPVERIFY | ssl_insecure_skip_verify |True or False
TYK_GW_DISABLEDASHBOARDZEROCONF | disable_dashboard_zeroconf |True or False
TYK_GW_SLAVEOPTIONS_USERPC | use_rpc |True or False
TYK_GW_SLAVEOPTIONS_USESSL | use_ssl |True or False
TYK_GW_SLAVEOPTIONS_SSLINSECURESKIPVERIFY | ssl_insecure_skip_verify |True or False
TYK_GW_SLAVEOPTIONS_CONNECTIONSTRING | connection_string |String
TYK_GW_SLAVEOPTIONS_RPCKEY | rpc_key |String
TYK_GW_SLAVEOPTIONS_APIKEY | api_key |String
TYK_GW_SLAVEOPTIONS_ENABLERPCCACHE | enable_rpc_cache |True or False
TYK_GW_SLAVEOPTIONS_BINDTOSLUGSINSTEADOFLISTENPATHS | bind_to_slugs |True or False
TYK_GW_SLAVEOPTIONS_DISABLEKEYSPACESYNC | disable_keyspace_sync |True or False
TYK_GW_SLAVEOPTIONS_GROUPID | group_id |String
TYK_GW_SLAVEOPTIONS_CALLTIMEOUT | call_timeout |Integer
TYK_GW_SLAVEOPTIONS_PINGTIMEOUT | ping_timeout |Integer
TYK_GW_SLAVEOPTIONS_RPCPOOLSIZE | rpc_pool_size |Integer
TYK_GW_MANAGEMENTNODE | management_node |True or False
TYK_GW_AUTHOVERRIDE_FORCEAUTHPROVIDER | force_auth_provider |True or False
TYK_GW_AUTHOVERRIDE_AUTHPROVIDER_NAME | name |AuthProviderCode
TYK_GW_AUTHOVERRIDE_AUTHPROVIDER_STORAGEENGINE | storage_engine |StorageEngineCode
TYK_GW_AUTHOVERRIDE_AUTHPROVIDER_META | meta |Comma-separated list of String:interface {} pairs
TYK_GW_AUTHOVERRIDE_FORCESESSIONPROVIDER | force_session_provider |True or False
TYK_GW_AUTHOVERRIDE_SESSIONPROVIDER_NAME | name |SessionProviderCode
TYK_GW_AUTHOVERRIDE_SESSIONPROVIDER_STORAGEENGINE | storage_engine |StorageEngineCode
TYK_GW_AUTHOVERRIDE_SESSIONPROVIDER_META | meta |Comma-separated list of String:interface {} pairs
TYK_GW_ENABLENONTRANSACTIONALRATELIMITER | enable_non_transactional_rate_limiter |True or False
TYK_GW_ENABLESENTINELRATELIMITER | enable_sentinel_rate_limiter |True or False
TYK_GW_ENABLEREDISROLLINGLIMITER | enable_redis_rolling_limiter |True or False
TYK_GW_DRLNOTIFICATIONFREQUENCY | drl_notification_frequency |Integer
TYK_GW_DRLTHRESHOLD | drl_threshold |Float
TYK_GW_ENFORCEORGDATAAGE | enforce_org_data_age |True or False
TYK_GW_ENFORCEORGDATADETAILLOGGING | enforce_org_data_detail_logging |True or False
TYK_GW_ENFORCEORGQUOTAS | enforce_org_quotas |True or False
TYK_GW_EXPERIMENTALPROCESSORGOFFTHREAD | experimental_process_org_off_thread |True or False
TYK_GW_MONITOR_ENABLETRIGGERMONITORS | enable_trigger_monitors |True or False
TYK_GW_MONITOR_CONFIG_METHOD | method |String
TYK_GW_MONITOR_CONFIG_TARGETPATH | target_path |String
TYK_GW_MONITOR_CONFIG_TEMPLATEPATH | template_path |String
TYK_GW_MONITOR_CONFIG_HEADERLIST | header_map |Comma-separated list of String:String pairs
TYK_GW_MONITOR_CONFIG_EVENTTIMEOUT | event_timeout |Integer
TYK_GW_MONITOR_GLOBALTRIGGERLIMIT | global_trigger_limit |Float
TYK_GW_MONITOR_MONITORUSERKEYS | monitor_user_keys |True or False
TYK_GW_MONITOR_MONITORORGKEYS | monitor_org_keys |True or False
TYK_GW_MAXIDLECONNS | max_idle_connections |Integer
TYK_GW_MAXIDLECONNSPERHOST | max_idle_connections_per_host |Integer
TYK_GW_MAXCONNTIME | max_conn_time |Integer
TYK_GW_CLOSEIDLECONNECTIONS | close_idle_connections |True or False
TYK_GW_CLOSECONNECTIONS | close_connections |True or False
TYK_GW_ENABLECUSTOMDOMAINS | enable_custom_domains |True or False
TYK_GW_ALLOWMASTERKEYS | allow_master_keys |True or False
TYK_GW_SERVICEDISCOVERY_DEFAULTCACHETIMEOUT | default_cache_timeout |Integer
TYK_GW_PROXYSSLINSECURESKIPVERIFY | proxy_ssl_insecure_skip_verify |True or False
TYK_GW_PROXYENABLEHTTP2 | proxy_enable_http2 |True or False
TYK_GW_PROXYSSLMINVERSION | proxy_ssl_min_version |Unsigned Integer
TYK_GW_PROXYSSLCIPHERSUITES | proxy_ssl_ciphers |Comma-separated list of String
TYK_GW_PROXYDEFAULTTIMEOUT | proxy_default_timeout |Float
TYK_GW_PROXYSSLDISABLERENEGOTIATION | proxy_ssl_disable_renegotiation |True or False
TYK_GW_PROXYCLOSECONNECTIONS | proxy_close_connections |True or False
TYK_GW_UPTIMETESTS_DISABLE | disable |True or False
TYK_GW_UPTIMETESTS_CONFIG_FAILURETRIGGERSAMPLESIZE | failure_trigger_sample_size |Integer
TYK_GW_UPTIMETESTS_CONFIG_TIMEWAIT | time_wait |Integer
TYK_GW_UPTIMETESTS_CONFIG_CHECKERPOOLSIZE | checker_pool_size |Integer
TYK_GW_UPTIMETESTS_CONFIG_ENABLEUPTIMEANALYTICS | enable_uptime_analytics |True or False
TYK_GW_HEALTHCHECK_ENABLEHEALTHCHECKS | enable_health_checks |True or False
TYK_GW_HEALTHCHECK_HEALTHCHECKVALUETIMEOUT | health_check_value_timeouts |Integer
TYK_GW_OAUTHREFRESHEXPIRE | oauth_refresh_token_expire |Integer
TYK_GW_OAUTHTOKENEXPIRE | oauth_token_expire |Integer
TYK_GW_OAUTHTOKENEXPIREDRETAINPERIOD | oauth_token_expired_retain_period |Integer
TYK_GW_OAUTHREDIRECTURISEPARATOR | oauth_redirect_uri_separator |String
TYK_GW_OAUTHERRORSTATUSCODE | oauth_error_status_code |Integer
TYK_GW_ENABLEKEYLOGGING | enable_key_logging |True or False
TYK_GW_SSLFORCECOMMONNAMECHECK | ssl_force_common_name_check |True or False
TYK_GW_ENABLEANALYTICS | enable_analytics |True or False
TYK_GW_ANALYTICSCONFIG_TYPE | type |String
TYK_GW_ANALYTICSCONFIG_IGNOREDIPS | ignored_ips |Comma-separated list of String
TYK_GW_ANALYTICSCONFIG_ENABLEDETAILEDRECORDING | enable_detailed_recording |True or False
TYK_GW_ANALYTICSCONFIG_ENABLEGEOIP | enable_geo_ip |True or False
TYK_GW_ANALYTICSCONFIG_GEOIPDBLOCATION | geo_ip_db_path |String
TYK_GW_ANALYTICSCONFIG_NORMALISEURLS_ENABLED | enabled |True or False
TYK_GW_ANALYTICSCONFIG_NORMALISEURLS_NORMALISEUUIDS | normalise_uuids |True or False
TYK_GW_ANALYTICSCONFIG_NORMALISEURLS_NORMALISENUMBERS | normalise_numbers |True or False
TYK_GW_ANALYTICSCONFIG_NORMALISEURLS_CUSTOM | custom_patterns |Comma-separated list of String
TYK_GW_ANALYTICSCONFIG_NORMALISEURLS_COMPILEDPATTERNSET_UUIDS_FROMCACHE |  |True or False
TYK_GW_ANALYTICSCONFIG_NORMALISEURLS_COMPILEDPATTERNSET_IDS_FROMCACHE |  |True or False
TYK_GW_ANALYTICSCONFIG_NORMALISEURLS_COMPILEDPATTERNSET_CUSTOM |  |Comma-separated list of 
TYK_GW_ANALYTICSCONFIG_POOLSIZE | pool_size |Integer
TYK_GW_ANALYTICSCONFIG_RECORDSBUFFERSIZE | records_buffer_size |Unsigned Integer
TYK_GW_ANALYTICSCONFIG_STORAGEEXPIRATIONTIME | storage_expiration_time |Integer
TYK_GW_LIVENESSCHECK_CHECKDURATION | check_duration |Duration
TYK_GW_DNSCACHE_ENABLED | enabled |True or False
TYK_GW_DNSCACHE_TTL | ttl |Integer
TYK_GW_DNSCACHE_MULTIPLEIPSHANDLESTRATEGY | multiple_ips_handle_strategy |IPsHandleStrategy
TYK_GW_DISABLEREGEXPCACHE | disable_regexp_cache |True or False
TYK_GW_REGEXPCACHEEXPIRE | regexp_cache_expire |Integer
TYK_GW_LOCALSESSIONCACHE_DISABLECACHESESSIONSTATE | disable_cached_session_state |True or False
TYK_GW_LOCALSESSIONCACHE_CACHEDSESSIONTIMEOUT | cached_session_timeout |Integer
TYK_GW_LOCALSESSIONCACHE_CACHESESSIONEVICTION | cached_session_eviction |Integer
TYK_GW_ENABLESEPERATECACHESTORE | enable_separate_cache_store |True or False
TYK_GW_CACHESTORAGE_TYPE | type |String
TYK_GW_CACHESTORAGE_HOST | host |String
TYK_GW_CACHESTORAGE_PORT | port |Integer
TYK_GW_CACHESTORAGE_HOSTS | hosts |Comma-separated list of String:String pairs
TYK_GW_CACHESTORAGE_ADDRS | addrs |Comma-separated list of String
TYK_GW_CACHESTORAGE_MASTERNAME | master_name |String
TYK_GW_CACHESTORAGE_USERNAME | username |String
TYK_GW_CACHESTORAGE_PASSWORD | password |String
TYK_GW_CACHESTORAGE_DATABASE | database |Integer
TYK_GW_CACHESTORAGE_MAXIDLE | optimisation_max_idle |Integer
TYK_GW_CACHESTORAGE_MAXACTIVE | optimisation_max_active |Integer
TYK_GW_CACHESTORAGE_TIMEOUT | timeout |Integer
TYK_GW_CACHESTORAGE_ENABLECLUSTER | enable_cluster |True or False
TYK_GW_CACHESTORAGE_USESSL | use_ssl |True or False
TYK_GW_CACHESTORAGE_SSLINSECURESKIPVERIFY | ssl_insecure_skip_verify |True or False
TYK_GW_ENABLEBUNDLEDOWNLOADER | enable_bundle_downloader |True or False
TYK_GW_BUNDLEBASEURL | bundle_base_url |String
TYK_GW_BUNDLEINSECURESKIPVERIFY | bundle_insecure_skip_verify |True or False
TYK_GW_ENABLEJSVM | enable_jsvm |True or False
TYK_GW_JSVMTIMEOUT | jsvm_timeout |Integer
TYK_GW_DISABLEVIRTUALPATHBLOBS | disable_virtual_path_blobs |True or False
TYK_GW_TYKJSPATH | tyk_js_path |String
TYK_GW_MIDDLEWAREPATH | middleware_path |String
TYK_GW_COPROCESSOPTIONS_ENABLECOPROCESS | enable_coprocess |True or False
TYK_GW_COPROCESSOPTIONS_COPROCESSGRPCSERVER | coprocess_grpc_server |String
TYK_GW_COPROCESSOPTIONS_GRPCRECVMAXSIZE | grpc_recv_max_size |Integer
TYK_GW_COPROCESSOPTIONS_GRPCSENDMAXSIZE | grpc_send_max_size |Integer
TYK_GW_COPROCESSOPTIONS_PYTHONPATHPREFIX | python_path_prefix |String
TYK_GW_COPROCESSOPTIONS_PYTHONVERSION | python_version |String
TYK_GW_IGNOREENDPOINTCASE | ignore_endpoint_case |True or False
TYK_GW_LOGLEVEL | log_level |String
TYK_GW_HEALTHCHECKENDPOINTNAME | health_check_endpoint_name |String
TYK_GW_TRACER_NAME | name |String
TYK_GW_TRACER_ENABLED | enabled |True or False
TYK_GW_TRACER_OPTIONS | options |Comma-separated list of String:interface {} pairs
TYK_GW_NEWRELIC_APPNAME | app_name |String
TYK_GW_NEWRELIC_LICENSEKEY | license_key |String
TYK_GW_HTTPPROFILE | enable_http_profiler |True or False
TYK_GW_USEREDISLOG | use_redis_log |True or False
TYK_GW_SENTRYCODE | sentry_code |String
TYK_GW_USESENTRY | use_sentry |True or False
TYK_GW_USESYSLOG | use_syslog |True or False
TYK_GW_USEGRAYLOG | use_graylog |True or False
TYK_GW_USELOGSTASH | use_logstash |True or False
TYK_GW_TRACK404LOGS | track_404_logs |True or False
TYK_GW_GRAYLOGNETWORKADDR | graylog_network_addr |String
TYK_GW_LOGSTASHNETWORKADDR | logstash_network_addr |String
TYK_GW_SYSLOGTRANSPORT | syslog_transport |String
TYK_GW_LOGSTASHTRANSPORT | logstash_transport |String
TYK_GW_SYSLOGNETWORKADDR | syslog_network_addr |String
TYK_GW_STATSDCONNECTIONSTRING | statsd_connection_string |String
TYK_GW_STATSDPREFIX | statsd_prefix |String
TYK_GW_EVENTHANDLERS_EVENTS | events |Comma-separated list of TykEvent:Comma-separated list of  pairs
TYK_GW_EVENTTRIGGERS | event_trigers_defunct |Comma-separated list of TykEvent:Comma-separated list of config.TykEventHandler pairs
TYK_GW_EVENTTRIGGERSDEFUNCT | event_triggers_defunct |Comma-separated list of TykEvent:Comma-separated list of config.TykEventHandler pairs
TYK_GW_SESSIONUPDATEPOOLSIZE | session_update_pool_size |Integer
TYK_GW_SESSIONUPDATEBUFFERSIZE | session_update_buffer_size |Integer
TYK_GW_SUPRESSDEFAULTORGSTORE | suppress_default_org_store |True or False
TYK_GW_LEGACYENABLEALLOWANCECOUNTDOWN | legacy_enable_allowance_countdown |True or False
TYK_GW_GLOBALSESSIONLIFETIME | global_session_lifetime |Integer
TYK_GW_FORCEGLOBALSESSIONLIFETIME | force_global_session_lifetime |True or False
TYK_GW_HIDEGENERATORHEADER | hide_generator_header |True or False
TYK_GW_KV_CONSUL_ADDRESS | address |String
TYK_GW_KV_CONSUL_SCHEME | scheme |String
TYK_GW_KV_CONSUL_DATACENTER | datacenter |String
TYK_GW_KV_CONSUL_HTTPAUTH_USERNAME | username |String
TYK_GW_KV_CONSUL_HTTPAUTH_PASSWORD | password |String
TYK_GW_KV_CONSUL_WAITTIME | wait_time |Duration
TYK_GW_KV_CONSUL_TOKEN | token |String
TYK_GW_KV_CONSUL_TLSCONFIG_ADDRESS | address |String
TYK_GW_KV_CONSUL_TLSCONFIG_CAFILE | ca_file |String
TYK_GW_KV_CONSUL_TLSCONFIG_CAPATH | ca_path |String
TYK_GW_KV_CONSUL_TLSCONFIG_CERTFILE | cert_file |String
TYK_GW_KV_CONSUL_TLSCONFIG_KEYFILE | key_file |String
TYK_GW_KV_CONSUL_TLSCONFIG_INSECURESKIPVERIFY | insecure_skip_verify |True or False
TYK_GW_KV_VAULT_ADDRESS | address |String
TYK_GW_KV_VAULT_AGENTADDRESS | agent_address |String
TYK_GW_KV_VAULT_MAXRETRIES | max_retries |Integer
TYK_GW_KV_VAULT_TIMEOUT | timeout |Duration
TYK_GW_KV_VAULT_TOKEN | token |String
TYK_GW_KV_VAULT_KVVERSION | kv_version |Integer
TYK_GW_SECRETS | secrets |Comma-separated list of String:String pairs
TYK_GW_OVERRIDEMESSAGES | override_messages |Comma-separated list of String: pairs


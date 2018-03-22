package lint

const confSchema = `{
"$schema": "http://json-schema.org/draft-04/schema#",
"type": "object",
"additionalProperties": false,
"definitions": {
	"StorageOptions": {
		"type": ["object", "null"],
		"additionalProperties": false,
		"properties": {
			"database": {
				"type": "integer"
			},
			"enable_cluster": {
				"type": "boolean"
			},
			"use_ssl":{
				"type": "boolean"
			},
			"ssl_insecure_skip_verify":{
				"type": "boolean"
			},
			"host": {
				"type": "string",
				"format": "host-no-port"
			},
			"hosts": {
				"type": ["array", "null"]
			},
			"optimisation_max_active": {
				"type": "integer"
			},
			"optimisation_max_idle": {
				"type": "integer"
			},
			"password": {
				"type": "string"
			},
			"port": {
				"type": "integer"
			},
			"type": {
				"type": "string",
				"enum": ["", "redis"]
			},
			"username": {
				"type": "string"
			}
		}
	}
},
"properties": {
	"allow_insecure_configs": {
		"type": "boolean"
	},
	"allow_master_keys": {
		"type": "boolean"
	},
	"allow_remote_config": {
		"type": "boolean"
	},
	"analytics_config": {
		"type": ["object", "null"],
		"additionalProperties": false,
		"properties": {
			"enable_detailed_recording": {
				"type": "boolean"
			},
			"enable_geo_ip": {
				"type": "boolean"
			},
			"geo_ip_db_path": {
				"type": "string",
				"format": "path"
			},
			"ignored_ips": {
				"type": ["array", "null"]
			},
			"normalise_urls": {
				"type": ["object", "null"],
				"additionalProperties": false,
				"properties": {
					"custom_patterns": {
						"type": ["array", "null"]
					},
					"enabled": {
						"type": "boolean"
					},
					"normalise_numbers": {
						"type": "boolean"
					},
					"normalise_uuids": {
						"type": "boolean"
					}
				}
			},
			"pool_size": {
				"type": "integer"
			},
			"storage_expiration_time": {
				"type": "integer"
			},
			"type": {
				"type": "string"
			}
		}
	},
	"app_path": {
		"type": "string",
		"format": "path"
	},
	"auth_override": {
		"type": ["object", "null"],
		"additionalProperties": false,
		"properties": {
			"auth_provider": {
				"type": ["object", "null"],
				"additionalProperties": false,
				"properties": {
					"meta": {
						"type": ["array", "null"]
					},
					"name": {
						"type": "string"
					},
					"storage_engine": {
						"type": "string"
					}
				}
			},
			"force_auth_provider": {
				"type": "boolean"
			},
			"force_session_provider": {
				"type": "boolean"
			},
			"session_provider": {
				"type": ["object", "null"],
				"additionalProperties": false,
				"properties": {
					"meta": {
						"type": ["array", "null"]
					},
					"name": {
						"type": "string"
					},
					"storage_engine": {
						"type": "string"
					}
				}
			}
		}
	},
	"bundle_base_url": {
		"type": "string"
	},
	"cache_storage": {
		"$ref": "#/definitions/StorageOptions"
	},
	"close_connections": {
		"type": "boolean"
	},
	"proxy_close_connections": {
		"type": "boolean"
	},
	"close_idle_connections": {
		"type": "boolean"
	},
	"control_api_hostname": {
		"type": "string"
	},
	"control_api_port": {
		"type": "integer"
	},
	"coprocess_options": {
		"type": ["object", "null"],
		"additionalProperties": false,
		"properties": {
			"coprocess_grpc_server": {
				"type": "string"
			},
			"enable_coprocess": {
				"type": "boolean"
			},
			"python_path_prefix": {
				"type": "string"
			}
		}
	},
	"db_app_conf_options": {
		"type": ["object", "null"],
		"additionalProperties": false,
		"properties": {
			"connection_string": {
				"type": "string"
			},
			"node_is_segmented": {
				"type": "boolean"
			},
			"tags": {
				"type": ["array", "null"],
				"items": {
					"type": "string"
				}
			}
		}
	},
	"version_header":{
		"type": "string"
	},
	"disable_dashboard_zeroconf": {
		"type": "boolean"
	},
	"disable_virtual_path_blobs": {
		"type": "boolean"
	},
	"drl_notification_frequency": {
		"type": "integer"
	},
	"enable_analytics": {
		"type": "boolean"
	},
	"enable_api_segregation": {
		"type": "boolean"
	},
	"enable_bundle_downloader": {
		"type": "boolean"
	},
	"enable_custom_domains": {
		"type": "boolean"
	},
	"enable_jsvm": {
		"type": "boolean"
	},
	"jsvm_timeout": {
		"type": "integer"
	},
	"enable_non_transactional_rate_limiter": {
		"type": "boolean"
	},
	"enable_redis_rolling_limiter": {
		"type": "boolean"
	},
	"enable_sentinel_rate_limiter": {
		"type": "boolean"
	},
	"enable_separate_cache_store": {
		"type": "boolean"
	},
	"enforce_org_data_age": {
		"type": "boolean"
	},
	"enforce_org_data_detail_logging": {
		"type": "boolean"
	},
	"enforce_org_quotas": {
		"type": "boolean"
	},
	"event_handlers": {
		"type": ["object", "null"],
		"additionalProperties": false,
		"properties": {
			"events": {
				"type": ["object", "null"],
				"additionalProperties": false
			}
		}
	},
	"event_trigers_defunct": {
		"type": ["array", "null"]
	},
	"experimental_process_org_off_thread": {
		"type": "boolean"
	},
	"force_global_session_lifetime": {
		"type": "boolean"
	},
	"global_session_lifetime": {
		"type": "integer"
	},
	"graylog_network_addr": {
		"type": "string"
	},
	"hash_keys": {
		"type": "boolean"
	},
	"health_check": {
		"type": ["object", "null"],
		"additionalProperties": false,
		"properties": {
			"enable_health_checks": {
				"type": "boolean"
			},
			"health_check_value_timeouts": {
				"type": "integer"
			}
		}
	},
	"hide_generator_header": {
		"type": "boolean"
	},
	"hostname": {
		"type": "string"
	},
	"http_server_options": {
		"type": ["object", "null"],
		"additionalProperties": false,
		"properties": {
			"certificates": {
				"type": ["array", "null"],
				"items": {
					"type": ["object", "null"],
					"additionalProperties": false,
					"properties": {
						"domain_name": {
							"type": "string"
						},
						"cert_file": {
							"type": "string"
						},
						"key_file": {
							"type": "string"
						}
					}
				}
			},
			"enable_websockets": {
				"type": "boolean"
			},
			"flush_interval": {
				"type": "integer"
			},
			"min_version": {
				"type": "integer"
			},
			"override_defaults": {
				"type": "boolean"
			},
			"read_timeout": {
				"type": "integer"
			},
			"server_name": {
				"type": "string"
			},
			"skip_url_cleaning": {
				"type": "boolean"
			},
			"skip_target_path_escaping": {
				"type": "boolean"
			},
			"ssl_insecure_skip_verify": {
				"type": "boolean"
			},
			"use_ssl": {
				"type": "boolean"
			},
			"use_ssl_le": {
				"type": "boolean"
			},
			"write_timeout": {
				"type": "integer"
			},
			"ssl_certificates": {
				"type": ["array", "null"],
				"items": {
					"type": "string"
				}
			},
			"ssl_ciphers":{
				"type": ["array", "null"],
				"items": {
					"type": "string"
				}
			}
		}
	},
	"legacy_enable_allowance_countdown": {
		"type": "boolean"
	},
	"listen_address": {
		"type": "string",
		"format": "host-no-port"
	},
	"listen_port": {
		"type": "integer"
	},
	"local_session_cache": {
		"type": ["object", "null"],
		"additionalProperties": false,
		"properties": {
			"cached_session_eviction": {
				"type": "integer"
			},
			"cached_session_timeout": {
				"type": "integer"
			},
			"disable_cached_session_state": {
				"type": "boolean"
			}
		}
	},
	"log_level": {
		"type": "string",
		"enum": ["", "debug", "info", "warn", "error"]
	},
	"logstash_network_addr": {
		"type": "string"
	},
	"logstash_transport": {
		"type": "string"
	},
	"management_node": {
		"type": "boolean"
	},
	"max_idle_connections_per_host": {
		"type": "integer"
	},
	"max_conn_time": {
		"type": "integer"
	},
	"middleware_path": {
		"type": "string",
		"format": "path"
	},
	"monitor": {
		"type": ["object", "null"],
		"additionalProperties": false,
		"properties": {
			"configuration": {
				"type": ["object", "null"],
				"additionalProperties": false,
				"properties": {
					"event_timeout": {
						"type": "integer"
					},
					"header_map": {
						"type": ["array", "null"]
					},
					"method": {
						"type": "string"
					},
					"target_path": {
						"type": "string"
					},
					"template_path": {
						"type": "string",
						"format": "path"
					}
				}
			},
			"enable_trigger_monitors": {
				"type": "boolean"
			},
			"global_trigger_limit": {
				"type": "integer"
			},
			"monitor_org_keys": {
				"type": "boolean"
			},
			"monitor_user_keys": {
				"type": "boolean"
			}
		}
	},
	"node_secret": {
		"type": "string"
	},
	"oauth_redirect_uri_separator": {
		"type": "string"
	},
	"oauth_refresh_token_expire": {
		"type": "integer"
	},
	"oauth_token_expire": {
		"type": "integer"
	},
	"oauth_token_expired_retain_period": {
		"type": "integer"
	},
	"optimisations_use_async_session_write": {
		"type": "boolean"
	},
	"pid_file_location": {
		"type": "string"
	},
	"policies": {
		"type": ["object", "null"],
		"additionalProperties": false,
		"properties": {
			"allow_explicit_policy_id": {
				"type": "boolean"
			},
			"policy_connection_string": {
				"type": "string"
			},
			"policy_record_name": {
				"type": "string"
			},
			"policy_source": {
				"type": "string",
				"enum": ["", "service", "rpc"]
			}
		}
	},
	"proxy_default_timeout": {
		"type": "integer"
	},
	"proxy_ssl_insecure_skip_verify": {
		"type": "boolean"
	},
	"public_key_path": {
		"type": "string",
		"format": "path"
	},
	"reload_wait_time": {
		"type": "integer"
	},
	"secret": {
		"type": "string"
	},
	"sentry_code": {
		"type": "string"
	},
	"service_discovery": {
		"type": ["object", "null"],
		"additionalProperties": false,
		"properties": {
			"default_cache_timeout": {
				"type": "integer"
			}
		}
	},
	"slave_options": {
		"type": ["object", "null"],
		"additionalProperties": false,
		"properties": {
			"api_key": {
				"type": "string"
			},
			"bind_to_slugs": {
				"type": "boolean"
			},
			"call_timeout": {
				"type": "integer"
			},
			"connection_string": {
				"type": "string"
			},
			"disable_keyspace_sync": {
				"type": "boolean"
			},
			"enable_rpc_cache": {
				"type": "boolean"
			},
			"group_id": {
				"type": "string"
			},
			"ping_timeout": {
				"type": "integer"
			},
			"rpc_key": {
				"type": "string"
			},
			"ssl_insecure_skip_verify": {
				"type": "boolean"
			},
			"use_rpc": {
				"type": "boolean"
			},
			"use_ssl": {
				"type": "boolean"
			},
			"rpc_pool_size": {
				"type": "integer"
			}
		}
	},
	"statsd_connection_string": {
		"type": "string"
	},
	"statsd_prefix": {
		"type": "string"
	},
	"storage": {
		"$ref": "#/definitions/StorageOptions"
	},
	"suppress_default_org_store": {
		"type": "boolean"
	},
	"suppress_redis_signal_reload": {
		"type": "boolean"
	},
	"syslog_network_addr": {
		"type": "string"
	},
	"syslog_transport": {
		"type": "string"
	},
	"template_path": {
		"type": "string",
		"format": "path"
	},
	"tyk_js_path": {
		"type": "string",
		"format": "path"
	},
	"uptime_tests": {
		"type": ["object", "null"],
		"additionalProperties": false,
		"properties": {
			"config": {
				"type": ["object", "null"],
				"additionalProperties": false,
				"properties": {
					"checker_pool_size": {
						"type": "integer"
					},
					"enable_uptime_analytics": {
						"type": "boolean"
					},
					"failure_trigger_sample_size": {
						"type": "integer"
					},
					"time_wait": {
						"type": "integer"
					}
				}
			},
			"disable": {
				"type": "boolean"
			}
		}
	},
	"use_db_app_configs": {
		"type": "boolean"
	},
	"use_graylog": {
		"type": "boolean"
	},
	"use_logstash": {
		"type": "boolean"
	},
	"use_redis_log": {
		"type": "boolean"
	},
	"use_sentry": {
		"type": "boolean"
	},
	"use_syslog": {
		"type": "boolean"
	},
	"security": {
		"type": ["object", "null"],
		"additionalProperties": false,
		"properties": {
			"private_certificate_encoding_secret": {
				"type": "string"
			},
			"control_api_use_mutual_tls": {
				"type": "boolean"
			},
			"certificates": {
				"type": ["object", "null"],
				"additionalProperties": false,
				"properties": {
					"upstream": {
						"type": ["object", "null"]
					},
					"apis": {
						"type": ["array", "null"],
						"items": {
							"type": "string"
						}
					},
					"control_api": {
						"type": ["array", "null"],
						"items": {
							"type": "string"
						}
					},
					"dashboard_api": {
						"type": ["array", "null"],
						"items": {
							"type": "string"
						}
					},
					"mdcb_api": {
						"type": ["array", "null"],
						"items": {
							"type": "string"
						}
					}
				}
			}
		}
	},
	"enable_key_logging": {
		"type": "boolean"
	},
	"newrelic": {
		"type": ["object", "null"],
		"additionalProperties": false,
		"properties": {
			"app_name": {
				"type": "string"
			},
			"license_key": {
				"type": "string"
			}
		}
	},
	"enable_hashed_keys_listing": {
		"type": "boolean"
	}
}
}`

package lint

const confSchema = `{
"$schema": "http://json-schema.org/draft-04/schema#",
"type": "object",
"properties": {
	"allow_insecure_configs": {
		"type": "boolean"
	},
	"allow_master_keys": {
		"type": "boolean"
	},
	"analytics_config": {
		"type": ["object", "null"],
		"properties": {
			"enable_detailed_recording": {
				"type": "boolean"
			},
			"enable_geo_ip": {
				"type": "boolean"
			},
			"geo_ip_db_path": {
				"type": "string"
			},
			"ignored_ips": {
				"type": ["array", "null"]
			},
			"normalise_urls": {
				"type": ["object", "null"],
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
			"type": {
				"type": "string"
			}
		}
	},
	"app_path": {
		"type": "string"
	},
	"close_connections": {
		"type": "boolean"
	},
	"control_api_hostname": {
		"type": "string"
	},
	"db_app_conf_options": {
		"type": ["object", "null"],
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
	"disable_dashboard_zeroconf": {
		"type": "boolean"
	},
	"disable_virtual_path_blobs": {
		"type": "boolean"
	},
	"enable_analytics": {
		"type": "boolean"
	},
	"enable_api_segregation": {
		"type": "boolean"
	},
	"enable_coprocess": {
		"type": "boolean"
	},
	"enable_custom_domains": {
		"type": "boolean"
	},
	"enable_jsvm": {
		"type": "boolean"
	},
	"enable_non_transactional_rate_limiter": {
		"type": "boolean"
	},
	"enable_sentinel_rate_limiter": {
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
		"properties": {
			"events": {
				"type": ["object", "null"]
			}
		}
	},
	"experimental_process_org_off_thread": {
		"type": "boolean"
	},
	"graylog_network_addr": {
		"type": "string"
	},
	"hash_keys": {
		"type": "boolean"
	},
	"health_check": {
		"type": ["object", "null"],
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
		"properties": {
			"certificates": {
				"type": ["array", "null"],
				"items": {
					"type": ["object", "null"],
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
			"use_ssl": {
				"type": "boolean"
			},
			"write_timeout": {
				"type": "integer"
			}
		}
	},
	"listen_address": {
		"type": "string"
	},
	"listen_port": {
		"type": "integer"
	},
	"local_session_cache": {
		"type": ["object", "null"],
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
	"logstash_network_addr": {
		"type": "string"
	},
	"logstash_transport": {
		"type": "string"
	},
	"middleware_path": {
		"type": "string"
	},
	"monitor": {
		"type": ["object", "null"],
		"properties": {
			"enable_trigger_monitors": {
				"type": "boolean"
			},
			"configuration": {
				"type": ["object", "null"],
				"properties": {
					"method": {
						"type": "string"
					},
					"target_path": {
						"type": "string"
					},
					"template_path": {
						"type": "string"
					},
					"header_map": {
						"type": ["object", "null"],
						"properties": {
							"x-tyk-monitor-secret": {
								"type": "string"
							}
						}
					},
					"event_timeout": {
						"type": "integer"
					}
				}
			},
			"global_trigger_limit": {
				"type": "integer"
			},
			"monitor_user_keys": {
				"type": "boolean"
			},
			"monitor_org_keys": {
				"type": "boolean"
			}
		}
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
	"optimisations_use_async_session_write": {
		"type": "boolean"
	},
	"pid_file_location": {
		"type": "string"
	},
	"policies": {
		"type": ["object", "null"],
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
				"type": "string"
			}
		}
	},
	"public_key_path": {
		"type": "string"
	},
	"sentry_code": {
		"type": "string"
	},
	"service_discovery": {
		"type": ["object", "null"],
		"properties": {
			"default_cache_timeout": {
				"type": "integer"
			}
		}
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
		"type": "string"
	},
	"tyk_js_path": {
		"type": "string"
	},
	"uptime_tests": {
		"type": ["object", "null"],
		"properties": {
			"config": {
				"type": ["object", "null"],
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
	}
}
}`

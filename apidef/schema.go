package apidef

const Schema = `{
    "type": ["object", "null"],
    "$schema": "http://json-schema.org/draft-04/schema",
    "id": "http://jsonschema.net",
    "additionalProperties": false,
    "properties": {
        "is_site": {
            "type": "boolean"
        },
        "uptime_tests": {
            "type": ["object", "null"]
        },
        "expire_analytics_after": {
            "type": "number"
        },
        "id": {
            "type": "string"
        },
        "org_id": {
            "type": "string"
        },
        "api_id": {
            "type": "string"
        },
		"last_updated": {
            "type": "number"
        },
		"expiration": {
            "type": "string"
        },
        "tags_disabled": {
            "type": "boolean"
        },
        "enable_ip_whitelisting": {
            "type": "boolean"
        },
        "enable_ip_blacklisting": {
            "type": "boolean"
        },
        "enable_context_vars": {
            "type": "boolean"
        },
        "strip_auth_data": {
          "type": "boolean"
        },
        "do_not_track": {
            "type": "boolean"
        },
        "enable_jwt": {
            "type": "boolean"
        },
        "use_openid": {
            "type": "boolean"
        },
        "openid_options": {
            "type": ["object", "null"]
        },
        "use_standard_auth": {
            "type": "boolean"
        },
        "use_go_plugin_auth": {
            "type": "boolean"
        },
        "enable_coprocess_auth": {
            "type": "boolean"
        },
		"custom_plugin_auth_enabled": {
            "type": "boolean"
        },
        "jwt_skip_kid": {
            "type": "boolean"
        },
        "base_identity_provided_by": {
            "type": "string"
        },
        "disable_rate_limit": {
            "type": "boolean"
        },
        "disable_quota": {
            "type": "boolean"
        },
        "custom_middleware_bundle": {
            "type": "string"
        },
		"custom_middleware_bundle_disabled": {
           	"type": "boolean"
        },
        "jwt_policy_field_name": {
            "type": "string"
        },
        "jwt_default_policies": {
            "type": ["array", "null"]
        },
        "jwt_signing_method": {
            "type": "string"
        },
        "jwt_source": {
            "type": "string"
        },
        "jwt_identity_base_field": {
            "type": "string"
        },
        "jwt_client_base_field": {
            "type": "string"
        },
        "jwt_disable_issued_at_validation": {
            "type": "boolean"
        },
        "jwt_disable_expires_at_validation": {
            "type": "boolean"
        },
        "jwt_disable_not_before_validation": {
            "type": "boolean"
        },
        "jwt_issued_at_validation_skew": {
            "type": "number"
        },
        "jwt_expires_at_validation_skew": {
            "type": "number"
        },
        "jwt_not_before_validation_skew": {
            "type": "number"
        },
        "jwt_scope_to_policy_mapping": {
            "type": ["object", "null"]
        },
        "jwt_scope_claim_name": {
            "type": "string"
        },
		"scopes" : {
		"type":["object", "null"],
		"properties": {
			"jwt": {
				"type":["object", "null"],
				"properties" : {
					"scope_claim_name": {
						"type": "string"
					},
					"scope_to_policy": {
						"type":["object", "null"]
					}
				}
			},
			"oidc": {
				"type":["object", "null"],
				 "properties" : {
					 "scope_claim_name": {
						 "type": "string"
					 },
					 "scope_to_policy": {
						 "type":["object", "null"]
					 }
				 }
				}
			}
		},  
        "use_keyless": {
            "type": "boolean"
        },
        "use_basic_auth": {
            "type": "boolean"
        },
        "use_mutual_tls_auth": {
            "type": "boolean"
        },
        "client_certificates": {
            "type": ["array", "null"]
        },
        "upstream_certificates": {
            "type": ["object", "null"]
        },
		"upstream_certificates_disabled": {
			"type": "boolean"
		},
        "pinned_public_keys": {
            "type": ["object", "null"]
        },
		"certificate_pinning_disabled": {
			"type": "boolean"
		},
        "allowed_ips": {
            "type": ["array", "null"]
        },
        "blacklisted_ips": {
            "type": ["array", "null"]
        },
        "enable_batch_request_support": {
            "type": "boolean"
        },
        "event_handlers": {
            "type":["object", "null"]
        },
        "notifications": {
            "type":["object", "null"]
        },
        "use_oauth2": {
            "type": "boolean"
        },
        "oauth_meta": {
            "type":["object", "null"]
        },
		"external_oauth": {
            "type":["object", "null"]
        },
        "cache_options": {
            "type":["object", "null"]
        },
        "tags": {
            "type": ["array", "null"]
        },
        "tag_headers": {
            "type": ["array", "null"]
        },
        "basic_auth": {
            "type": ["object", "null"]
        },
        "CORS": {
            "type":["object", "null"]
        },
        "response_processors": {
            "type": ["array", "null"]
        },
        "auth_provider": {
            "type":["object", "null"],
            "properties": {
                "name": {
                    "type": "string",
                    "enum": [""]
                },
                "storage_engine": {
                    "type": "string",
                    "enum": [""]
                }
            }
        },
        "session_provider": {
            "type":["object", "null"],
            "properties": {
                "name": {
                    "type": "string",
                    "enum": [""]
                },
                "storage_engine": {
                    "type": "string",
                    "enum": [""]
                }
            }
        },
        "hmac_allowed_clock_skew": {
            "type": "number"
        },
        "hmac_allowed_algorithms": {
            "type": ["array", "null"]
        },
        "dont_set_quota_on_create": {
            "type": "boolean"
            },
        "custom_middleware": {
            "type":["object", "null"],
            "properties": {
                "pre": {
                    "type": ["array", "null"]
                },
                "post": {
                    "type": ["array", "null"]
                }
            }
        },
        "session_lifetime_respects_key_expiration": {
            "type": "boolean"
        },
        "session_lifetime": {
            "type": "number"
        },
        "enable_detailed_recording": {
            "type": "boolean"
        },
        "enable_signature_checking": {
            "type": "boolean"
        },
        "active": {
            "type": "boolean"
        },
        "internal": {
            "type": "boolean"
        },
        "auth": {
            "type": ["object", "null"],
            "id": "http://jsonschema.net/auth",
            "properties": {
                "auth_header_name": {
                    "type": "string",
                    "id": "http://jsonschema.net/auth/auth_header_name"
                },
                "use_certificate": {
                    "type": "boolean"
                }
            }
        },
        "auth_configs":{
            "type": ["object", "null"]
        },
        "definition": {
            "type": ["object", "null"],
            "id": "http://jsonschema.net/definition",
            "properties": {
                "key": {
                    "type": "string",
                    "id": "http://jsonschema.net/definition/key"
                },
                "location": {
                    "type": "string",
                    "id": "http://jsonschema.net/definition/location"
                },
                "strip_path": {
                    "type": "boolean",
                    "id": "http://jsonschema.net/definition/location"
                }
            },
            "required": [
                "key",
                "location"
            ]
        },
        "name": {
            "type": "string",
            "id": "http://jsonschema.net/name"
        },
        "slug": {
            "type": "string",
            "pattern": "[a-zA-Z0-9]*",
            "id": "http://jsonschema.net/name"
        },
        "domain": {
            "type": "string"
        },
        "domain_disabled": {
             "type": "boolean"
        },
        "listen_port": {
            "type": "number"
        },
        "protocol": {
            "type": "string"
        },
        "enable_proxy_protocol": {
            "type": "boolean"
        },
        "certificates": {
            "type": ["array", "null"]
        },
        "check_host_against_uptime_tests": {
            "type": "boolean"
        },
        "proxy": {
            "type": ["object", "null"],
            "id": "http://jsonschema.net/proxy",
            "properties": {
                "target_url": {
                    "type": "string",
                    "id": "http://jsonschema.net/proxy/target_url"
                },
                "check_host_against_uptime_tests": {
                    "type": "boolean"
                },
                "preserve_host_header": {
                    "type": "boolean"
                },
                "transport": {
                    "type": ["object", "null"],
                    "properties": {
                        "ssl_ciphers": {
                            "type": ["array", "null"]
                        },
                        "ssl_min_version": {
                            "type": "number"
                        },
                        "ssl_max_version": {
                            "type": "number"
                        },
                        "proxy_url": {
                            "type": "string"
                        },
                        "ssl_force_common_name_check": {
                            "type": "boolean"
                        }
                    }
                }
            },
            "required": [
                "target_url"
            ]
        },
        "hook_references": {
            "type": ["object", "null"]
        },
        "version_data": {
            "type": ["object", "null"],
            "id": "http://jsonschema.net/version_data",
            "properties": {
                "not_versioned": {
                    "type": "boolean",
                    "id": "http://jsonschema.net/version_data/not_versioned"
                },
                "default_version":{
                    "type": "string",
                    "id": "http://jsonschema.net/version_data/default_version"
                },
                "versions": {
                    "type": ["object", "null"],
                    "id": "http://jsonschema.net/version_data/versions",
                    "patternProperties": {
                        "^[a-zA-Z0-9]+$": {
                            "title": "versionInfoProperty",
                            "type": ["object", "null"],
                            "id": "http://jsonschema.net/access_rights/versionInfoProperty",
                            "properties": {
                                "expires": {
                                    "type": "string",
                                    "id": "http://jsonschema.net/version_data/versions/versionInfoProperty/expires"
                                },
                                "name": {
                                    "type": "string",
                                    "id": "http://jsonschema.net/version_data/versions/versionInfoProperty/name"
                                },
                                "paths": {
                                    "type": ["object", "null"],
                                    "id": "http://jsonschema.net/version_data/versions/versionInfoProperty/paths",
                                    "properties": {
                                        "black_list": {
                                            "type": ["array", "null"],
                                            "id": "http://jsonschema.net/version_data/versions/versionInfoProperty/paths/black_list"
                                        },
                                        "ignored": {
                                            "type": ["array", "null"],
                                            "id": "http://jsonschema.net/version_data/versions/versionInfoProperty/paths/ignored"
                                        },
                                        "white_list": {
                                            "type": ["array", "null"],
                                            "id": "http://jsonschema.net/version_data/versions/versionInfoProperty/paths/white_list"
                                        }
                                    }
                                }
                            },
                            "required": [
                                "name"
                            ]
                        }
                    }
                }
            },
            "required": [
                "not_versioned",
                "versions"
            ]
        },
        "config_data": {
            "type": ["object", "null"]
        },
		"config_data_disabled": {
			"type": "boolean"	
		},
        "global_rate_limit": {
          "type": ["object", "null"],
           "properties": {
                "rate": {
                    "type": "number"
                },
                "per": {
                    "type": "number"
                }
            }
        },
    "request_signing": {
          "type": ["object", "null"],
           "properties": {
                "is_enabled": {
                    "type": "boolean"
                },
                "secret": {
                    "type": "string"
                },
        "key_id": {
                    "type": "string"
                },
        "algorithm": {
                    "type": "string"
                }
            },
        "required": [
            "is_enabled"
        ]
        },
        "graphql": {
            "type": ["object", "null"],
            "properties": {
                "enabled": {
                    "type": "boolean"
                },
                "version": {
                    "type": "string"
                },
                "execution_mode": {
                    "type": "string",
                    "enum": [
                        "proxyOnly",
                        "executionEngine",
                        "subgraph",
                        "supergraph",
                        ""
                    ]
                },
                "schema": {
                    "type": "string"
                },
                "last_schema_update": {
                    "type": "string",
                    "format": "date-time"
                },
                "type_field_configurations": {
                    "type": ["array", "null"],
                    "properties": {
                        "type_name": {
                            "type": "string"
                        },
                        "field_name": {
                            "type": "string"
                        },
                        "mapping": {
                            "type": ["object", "null"],
                            "properties": {
                                "disabled": {
                                    "type": "boolean"
                                },
                                "path": {
                                    "type": "string"
                                }
                            },
                            "required": [
                                "disabled"
                            ]
                        },
                        "data_source": {
                            "type": ["object", "null"],
                            "properties": {
                                "kind": {
                                    "type": "boolean"
                                },
                                "data_source_config": {
                                    "type": ["object", "null"]
                                }
                            },
                            "required": [
                                "kind"
                            ]
                        }
                    },
                    "required": [
                        "type_name",
                        "field_name"
                    ]
                },
                "engine": {
                    "type": ["object", "null"],
                    "properties": {
                        "field_configs": {
                            "type": ["array", "null"],
                            "properties": {
                                "type_name": {
                                    "type": "string"
                                },
                                "field_name": {
                                    "type": "string"
                                },
                                "disable_default_mapping": {
                                    "type": "boolean"
                                },
                                "path": {
                                    "type": ["array", "null"]
                                }
                            }
                        },
                        "data_sources": {
                            "type": ["array", "null"],
                            "properties": {
                                "kind": {
                                    "type": "string",
                                    "enum": [
                                        "REST",
                                        "GraphQL",
                                        ""
                                    ]
                                },
                                "name": {
                                    "type": "string"
                                },
                                "internal": {
                                    "type": "boolean"
                                },
                                "root_fields": {
                                    "type": ["array", "null"],
                                    "properties": {
                                        "type": {
                                            "type": "string"
                                        },
                                        "fields": {
                                            "type": ["array", "null"]
                                        }
                                    }
                                },
                                "config": {
                                    "type": ["object", "null"]
                                }
                            },
                            "required": [
                                "kind"
                            ]
                        }
                    }
                },
                "proxy": {
                    "type": ["object", "null"],
                    "properties": {
                        "auth_headers": {
                            "type": ["object", "null"]
                        }
                    }
                },
                "subgraph": {
                    "type": ["object", "null"],
                    "properties": {
                        "sdl": {
                            "type": "string"
                        }
                    }
                },
                "supergraph": {
                    "type": ["object", "null"],
                    "properties": {
                        "updated_at": {
                            "type": "string",
                            "format": "date-time"
                        },
                        "disable_query_batching": {
                            "type": "boolean"
                        },
                        "subgraphs": {
                            "type": ["array", "null"],
                            "properties": {
                                "api_id": {
                                    "type": "string"
                                },
                                "name": {
                                    "type": "string"
                                },
                                "url": {
                                    "type": "string"
                                },
                                "sdl": {
                                    "type": "string"
                                },
                                "headers": {
                                    "type": ["object", "null"]
                                }
                            }
                        },
                        "global_headers": {
                            "type": ["object", "null"]
                        },
                        "merged_sdl": {
                            "type": "string"
                        }
                    }
                },
                "playground": {
                    "type": ["object", "null"],
                    "properties": {
                        "enabled": {
                            "type": "boolean"
                        },
                        "path": {
                            "type": "string"
                        }
                    },
                    "required": [
                        "enabled"
                    ]
                }
            },
            "required": [
                "enabled"
            ]
        },
        "analytics_plugin": {
            "type": ["object", "null"],
            "properties": {
                "enabled": {
                    "type": "boolean"
                },
                "plugin_path": {
                    "type": "string"
                },
                "func_name": {
                    "type": "string"
                }
            }
        },
		"is_oas": {
			"type": "boolean"
		}
    },
    "required": [
        "name",
        "proxy",
        "version_data"
    ]
}`

package apidef

const Schema = `{
    "type": "object",
    "$schema": "http://json-schema.org/draft-04/schema",
    "id": "http://jsonschema.net",
    "additionalProperties": false,
    "properties": {
        "is_site": {
            "type": "boolean"
        },
        "uptime_tests": {
            "type": "object"
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
            "type": "object"
        },
        "use_standard_auth":{
            "type": "boolean"
        },
        "enable_coprocess_auth": {
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
        "jwt_policy_field_name": {
            "type": "string"
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
            "type": "array"
        },
        "upstream_certificates": {
            "type": "object"
        },
        "pinned_public_keys": {
            "type": "object"
        },
        "allowed_ips": {
            "type": "array"
        },
        "blacklisted_ips": {
            "type": "array"
        },
        "enable_batch_request_support": {
            "type": "boolean"
        },
        "event_handlers": {
            "type":"object"
        },
        "notifications": {
            "type":"object"
        },
        "use_oauth2": {
            "type": "boolean"
        },
        "oauth_meta": {
            "type":"object"
        },
        "cache_options": {
            "type":"object"
        },
        "tags": {
            "type":"array"
        },
        "tag_headers": {
            "type":"array"
        },
        "basic_auth": {
            "type": "object"
        },
        "CORS": {
            "type":"object"
        },
        "response_processors": {
            "type":"array"
        },
        "auth_provider": {
            "type":"object",
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
            "type":"object",
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
        "dont_set_quota_on_create": {
            "type": "boolean"
            },
        "custom_middleware": {
            "type":"object",
            "properties": {
                "pre": {
                    "type": ["array", "null"]
                },
                "post": {
                    "type": ["array", "null"]
                }
            }
        },
        "session_lifetime": {
            "type": "number"
        },
        "enable_signature_checking": {
            "type": "boolean"
        },
        "active": {
            "type": "boolean",
            "id": "http://jsonschema.net/active"
        },
        "auth": {
            "type": "object",
            "id": "http://jsonschema.net/auth",
            "properties": {
                "auth_header_name": {
                    "type": "string",
                    "id": "http://jsonschema.net/auth/auth_header_name"
                },
                "use_certificate": {
                    "type": "boolean"
                }
            },
            "required": [
                "auth_header_name"
            ]
        },
        "definition": {
            "type": "object",
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
        "check_host_against_uptime_tests": {
            "type": "boolean"
        },
        "proxy": {
            "type": "object",
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
                    "type": "object",
                    "properties": {
                        "ssl_ciphers": {
                            "type": ["array", "null"]
                        },
                        "ssl_min_version": {
                            "type": "number"
                        },
                        "proxy_url": {
                            "type": "string"
                        }
                    }
                }
            },
            "required": [
                "target_url"
            ]
        },
        "hook_references": {
            "type": "object"
        },
        "version_data": {
            "type": "object",
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
                    "type": "object",
                    "id": "http://jsonschema.net/version_data/versions",
                    "patternProperties": {
                        "^[a-zA-Z0-9]+$": {
                            "title": "versionInfoProperty",
                            "type": "object",
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
                                    "type": "object",
                                    "id": "http://jsonschema.net/version_data/versions/versionInfoProperty/paths",
                                    "properties": {
                                        "black_list": {
                                            "type": "array",
                                            "id": "http://jsonschema.net/version_data/versions/versionInfoProperty/paths/black_list"
                                        },
                                        "ignored": {
                                            "type": "array",
                                            "id": "http://jsonschema.net/version_data/versions/versionInfoProperty/paths/ignored"
                                        },
                                        "white_list": {
                                            "type": "array",
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
            "type": "object"
        },
        "global_rate_limit": {
          "type": "object",
           "properties": {
                "rate": {
                    "type": "number"
                },
                "per": {
                    "type": "number"
                }
            }
        }
    },
    "required": [
        "auth",
        "name",
        "proxy",
        "version_data"
    ]
}`

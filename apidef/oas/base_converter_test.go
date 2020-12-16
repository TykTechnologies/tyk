package oas

import (
	"encoding/json"
	"fmt"
	"github.com/TykTechnologies/tyk/apidef"
	"testing"
)

const api = `
{
    "id": "5fb66262bca82a1b1802af51",
    "name": "elma",
    "slug": "elma",
    "listen_port": 0,
    "protocol": "",
    "enable_proxy_protocol": false,
    "api_id": "b23cc61c8b1b471c7a42715dba60ae72",
    "org_id": "5fb65fedbca82a188a57ead9",
    "use_keyless": true,
    "use_oauth2": false,
    "use_openid": false,
    "openid_options": {
        "providers": [],
        "segregate_by_client": false
    },
    "oauth_meta": {
        "allowed_access_types": [],
        "allowed_authorize_types": [],
        "auth_login_redirect": ""
    },
    "auth": {
        "use_param": false,
        "param_name": "",
        "use_cookie": false,
        "cookie_name": "",
        "auth_header_name": "Authorization",
        "use_certificate": false,
        "validate_signature": false,
        "signature": {
            "algorithm": "",
            "header": "",
            "secret": "",
            "allowed_clock_skew": 0,
            "error_code": 0,
            "error_message": ""
        }
    },
    "auth_configs": {
        "authToken": {
            "use_param": false,
            "param_name": "",
            "use_cookie": false,
            "cookie_name": "",
            "auth_header_name": "Authorization",
            "use_certificate": false,
            "validate_signature": false,
            "signature": {
                "algorithm": "",
                "header": "",
                "secret": "",
                "allowed_clock_skew": 0,
                "error_code": 0,
                "error_message": ""
            }
        },
        "basic": {
            "use_param": false,
            "param_name": "",
            "use_cookie": false,
            "cookie_name": "",
            "auth_header_name": "Authorization",
            "use_certificate": false,
            "validate_signature": false,
            "signature": {
                "algorithm": "",
                "header": "",
                "secret": "",
                "allowed_clock_skew": 0,
                "error_code": 0,
                "error_message": ""
            }
        },
        "coprocess": {
            "use_param": false,
            "param_name": "",
            "use_cookie": false,
            "cookie_name": "",
            "auth_header_name": "Authorization",
            "use_certificate": false,
            "validate_signature": false,
            "signature": {
                "algorithm": "",
                "header": "",
                "secret": "",
                "allowed_clock_skew": 0,
                "error_code": 0,
                "error_message": ""
            }
        },
        "hmac": {
            "use_param": false,
            "param_name": "",
            "use_cookie": false,
            "cookie_name": "",
            "auth_header_name": "Authorization",
            "use_certificate": false,
            "validate_signature": false,
            "signature": {
                "algorithm": "",
                "header": "",
                "secret": "",
                "allowed_clock_skew": 0,
                "error_code": 0,
                "error_message": ""
            }
        },
        "jwt": {
            "use_param": false,
            "param_name": "",
            "use_cookie": false,
            "cookie_name": "",
            "auth_header_name": "Authorization",
            "use_certificate": false,
            "validate_signature": false,
            "signature": {
                "algorithm": "",
                "header": "",
                "secret": "",
                "allowed_clock_skew": 0,
                "error_code": 0,
                "error_message": ""
            }
        },
        "oauth": {
            "use_param": false,
            "param_name": "",
            "use_cookie": false,
            "cookie_name": "",
            "auth_header_name": "Authorization",
            "use_certificate": false,
            "validate_signature": false,
            "signature": {
                "algorithm": "",
                "header": "",
                "secret": "",
                "allowed_clock_skew": 0,
                "error_code": 0,
                "error_message": ""
            }
        },
        "oidc": {
            "use_param": false,
            "param_name": "",
            "use_cookie": false,
            "cookie_name": "",
            "auth_header_name": "Authorization",
            "use_certificate": false,
            "validate_signature": false,
            "signature": {
                "algorithm": "",
                "header": "",
                "secret": "",
                "allowed_clock_skew": 0,
                "error_code": 0,
                "error_message": ""
            }
        }
    },
    "use_basic_auth": false,
    "basic_auth": {
        "disable_caching": false,
        "cache_ttl": 0,
        "extract_from_body": false,
        "body_user_regexp": "",
        "body_password_regexp": ""
    },
    "use_mutual_tls_auth": false,
    "client_certificates": [],
    "upstream_certificates": {},
    "pinned_public_keys": {},
    "enable_jwt": false,
    "use_standard_auth": false,
    "use_go_plugin_auth": false,
    "enable_coprocess_auth": false,
    "jwt_signing_method": "",
    "jwt_source": "",
    "jwt_identity_base_field": "",
    "jwt_client_base_field": "",
    "jwt_policy_field_name": "",
    "jwt_default_policies": [],
    "jwt_issued_at_validation_skew": 0,
    "jwt_expires_at_validation_skew": 0,
    "jwt_not_before_validation_skew": 0,
    "jwt_skip_kid": false,
    "jwt_scope_to_policy_mapping": {},
    "jwt_scope_claim_name": "",
    "notifications": {
        "shared_secret": "",
        "oauth_on_keychange_url": ""
    },
    "enable_signature_checking": false,
    "hmac_allowed_clock_skew": -1,
    "hmac_allowed_algorithms": [],
    "request_signing": {
        "is_enabled": false,
        "secret": "",
        "key_id": "",
        "algorithm": "",
        "header_list": [],
        "certificate_id": "",
        "signature_header": ""
    },
    "base_identity_provided_by": "",
    "definition": {
        "location": "header",
        "key": "x-api-version",
        "strip_path": false
    },
    "version_data": {
        "not_versioned": true,
        "default_version": "",
        "versions": {
            "Default": {
                "name": "Default",
                "expires": "",
                "paths": {
                    "ignored": [],
                    "white_list": [],
                    "black_list": []
                },
                "use_extended_paths": true,
                "extended_paths": {
                    "white_list": [
                        {
                            "path": "/get",
                            "ignore_case": false,
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/ip",
                            "ignore_case": true,
                            "method_actions": {
                                "GET": {
                                    "action": "reply",
                                    "code": 201,
                                    "data": "mock-body",
                                    "headers": {}
                                }
                            }
                        }
                    ],
                    "transform_headers": [
                        {
                            "delete_headers": [
                                "del-req-header"
                            ],
                            "add_headers": {
                                "add-req-header": "add-req-header-val"
                            },
                            "path": "/get",
                            "method": "GET",
                            "act_on": false
                        }
                    ],
                    "transform_response_headers": [
                        {
                            "delete_headers": [
                                "furkan-delete-header"
                            ],
                            "add_headers": {
                                "furkan-add-header": "furkan-delete-header-val"
                            },
                            "path": "/furkan",
                            "method": "GET",
                            "act_on": false
                        },
                        {
                            "delete_headers": [
                                "del-res-header"
                            ],
                            "add_headers": {
                                "add-res-header": "add-res-header-val"
                            },
                            "path": "/get",
                            "method": "GET",
                            "act_on": false
                        }
                    ]
                },
                "global_headers": {
                    "global-add-req-header": "global-add-req-header-val"
                },
                "global_headers_remove": [
                    "global-del-req-header"
                ],
                "global_response_headers": {},
                "global_response_headers_remove": [],
                "ignore_endpoint_case": false,
                "global_size_limit": 0,
                "override_target": ""
            }
        }
    },
    "uptime_tests": {
        "check_list": [],
        "config": {
            "expire_utime_after": 0,
            "service_discovery": {
                "use_discovery_service": false,
                "query_endpoint": "",
                "use_nested_query": false,
                "parent_data_path": "",
                "data_path": "",
                "port_data_path": "",
                "target_path": "",
                "use_target_list": false,
                "cache_timeout": 60,
                "endpoint_returns_list": false
            },
            "recheck_wait": 0
        }
    },
    "proxy": {
        "preserve_host_header": false,
        "listen_path": "/elma/",
        "target_url": "http://httpbin.org",
        "disable_strip_slash": true,
        "strip_listen_path": true,
        "enable_load_balancing": false,
        "target_list": [],
        "check_host_against_uptime_tests": false,
        "service_discovery": {
            "use_discovery_service": false,
            "query_endpoint": "",
            "use_nested_query": false,
            "parent_data_path": "",
            "data_path": "",
            "port_data_path": "",
            "target_path": "",
            "use_target_list": false,
            "cache_timeout": 0,
            "endpoint_returns_list": false
        },
        "transport": {
            "ssl_insecure_skip_verify": false,
            "ssl_ciphers": [],
            "ssl_min_version": 0,
            "ssl_force_common_name_check": false,
            "proxy_url": ""
        }
    },
    "disable_rate_limit": false,
    "disable_quota": false,
    "custom_middleware": {
        "pre": [],
        "post": [],
        "post_key_auth": [],
        "auth_check": {
            "name": "",
            "path": "",
            "require_session": false,
            "raw_body_only": false
        },
        "response": [],
        "driver": "",
        "id_extractor": {
            "extract_from": "",
            "extract_with": "",
            "extractor_config": {}
        }
    },
    "custom_middleware_bundle": "",
    "cache_options": {
        "cache_timeout": 60,
        "enable_cache": true,
        "cache_all_safe_requests": false,
        "cache_response_codes": [],
        "enable_upstream_cache_control": false,
        "cache_control_ttl_header": "",
        "cache_by_headers": []
    },
    "session_lifetime": 0,
    "active": true,
    "internal": false,
    "auth_provider": {
        "name": "",
        "storage_engine": "",
        "meta": {}
    },
    "session_provider": {
        "name": "",
        "storage_engine": "",
        "meta": {}
    },
    "event_handlers": {
        "events": {}
    },
    "enable_batch_request_support": false,
    "enable_ip_whitelisting": true,
    "allowed_ips": [],
    "enable_ip_blacklisting": false,
    "blacklisted_ips": [],
    "dont_set_quota_on_create": false,
    "expire_analytics_after": 0,
    "response_processors": [
        {
            "name": "header_injector",
            "options": {}
        }
    ],
    "CORS": {
        "enable": false,
        "allowed_origins": [
            "*"
        ],
        "allowed_methods": [
            "GET",
            "POST",
            "HEAD"
        ],
        "allowed_headers": [
            "Origin",
            "Accept",
            "Content-Type",
            "X-Requested-With",
            "Authorization"
        ],
        "exposed_headers": [],
        "allow_credentials": false,
        "max_age": 24,
        "options_passthrough": false,
        "debug": false
    },
    "domain": "",
    "certificates": [],
    "do_not_track": false,
    "tags": [],
    "enable_context_vars": false,
    "config_data": {},
    "tag_headers": [],
    "global_rate_limit": {
        "rate": 0,
        "per": 0
    },
    "strip_auth_data": false,
    "enable_detailed_recording": false,
    "graphql": {
        "enabled": false,
        "execution_mode": "proxyOnly",
        "schema": "",
        "type_field_configurations": [],
        "playground": {
            "enabled": false,
            "path": ""
        }
    }
}
`

func TestConverter_TykAPIDefinitionToSwagger(t *testing.T) {
	a := apidef.APIDefinition{}
	if err := json.Unmarshal([]byte(api), &a); err != nil {
		panic(err)
	}

	c := Converter{}

	swagger := c.TykAPIDefinitionToSwagger(a, "Default")

	//inBytes, _ := json.MarshalIndent(swagger, "", "   ")
	//yml, _ := yaml.JSONToYAML(inBytes)
	//fmt.Println(string(yml))

	ax := c.SwaggerToTykAPIDefinition(swagger, "Default")
	inBytes, _ := json.MarshalIndent(ax, "", "   ")
	fmt.Println(string(inBytes))
}

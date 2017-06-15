package main

import (
	"testing"
)

const nonExpiringExtendedDef = `{
	"api_id": "1",
	"org_id": "default",
	"definition": {
		"location": "header",
		"key": "version"
	},
	"auth": {
		"auth_header_name": "authorization"
	},
	"version_data": {
		"versions": {
			"v1": {
				"name": "v1",
				"use_extended_paths": true,
				"extended_paths": {
					"ignored": [
						{
							"path": "/v1/ignored/noregex",
							"method_actions": {
								"GET": {
									"action": "no_action",
									"code": 200,
									"headers": {
										"x-tyk-override-test": "tyk-override",
										"x-tyk-override-test-2": "tyk-override-2"
									}
								}
							}
						},
						{
							"path": "/v1/ignored/with_id/{id}",
							"method_actions": {
								"GET": {
									"action": "no_action",
									"code": 200,
									"headers": {
										"x-tyk-override-test": "tyk-override",
										"x-tyk-override-test-2": "tyk-override-2"
									}
								}
							}
						}
					],
					"white_list": [
						{
							"path": "v1/allowed/whitelist/literal",
							"method_actions": {
								"GET": {
									"action": "no_action",
									"code": 200,
									"headers": {
										"x-tyk-override-test": "tyk-override",
										"x-tyk-override-test-2": "tyk-override-2"
									}
								}
							}
						},
						{
							"path": "v1/allowed/whitelist/reply/{id}",
							"method_actions": {
								"GET": {
									"action": "reply",
									"code": 200,
									"data": "flump",
									"headers": {
										"x-tyk-override-test": "tyk-override",
										"x-tyk-override-test-2": "tyk-override-2"
									}
								}
							}
						},
						{
							"path": "v1/allowed/whitelist/{id}",
							"method_actions": {
								"GET": {
									"action": "no_action",
									"code": 200,
									"headers": {
										"x-tyk-override-test": "tyk-override",
										"x-tyk-override-test-2": "tyk-override-2"
									}
								}
							}
						}
					],
					"black_list": [
						{
							"path": "v1/disallowed/blacklist/literal",
							"method_actions": {
								"GET": {
									"action": "no_action",
									"code": 200,
									"headers": {
										"x-tyk-override-test": "tyk-override",
										"x-tyk-override-test-2": "tyk-override-2"
									}
								}
							}
						},
						{
							"path": "v1/disallowed/blacklist/{id}",
							"method_actions": {
								"GET": {
									"action": "no_action",
									"code": 200,
									"headers": {
										"x-tyk-override-test": "tyk-override",
										"x-tyk-override-test-2": "tyk-override-2"
									}
								}
							}
						}
					]
				}
			}
		}
	},
	"proxy": {
		"listen_path": "/v1",
		"target_url": "` + testHttpAny + `"
	}
}`

const nonExpiringExtendedDefNoWhitelist = `{
	"api_id": "1",
	"org_id": "default",
	"definition": {
		"location": "header",
		"key": "version"
	},
	"auth": {
		"auth_header_name": "authorization"
	},
	"version_data": {
		"versions": {
			"v1": {
				"name": "v1",
				"use_extended_paths": true,
				"extended_paths": {
					"ignored": [
						{
							"path": "/v1/ignored/noregex",
							"method_actions": {
								"GET": {
									"action": "no_action",
									"code": 200,
									"headers": {
										"x-tyk-override-test": "tyk-override",
										"x-tyk-override-test-2": "tyk-override-2"
									}
								}
							}
						},
						{
							"path": "/v1/ignored/with_id/{id}",
							"method_actions": {
								"GET": {
									"action": "no_action",
									"code": 200,
									"headers": {
										"x-tyk-override-test": "tyk-override",
										"x-tyk-override-test-2": "tyk-override-2"
									}
								}
							}
						}
					],
					"black_list": [
						{
							"path": "v1/disallowed/blacklist/literal",
							"method_actions": {
								"GET": {
									"action": "no_action",
									"code": 200,
									"headers": {
										"x-tyk-override-test": "tyk-override",
										"x-tyk-override-test-2": "tyk-override-2"
									}
								}
							}
						},
						{
							"path": "v1/disallowed/blacklist/{id}",
							"method_actions": {
								"GET": {
									"action": "no_action",
									"code": 200,
									"headers": {
										"x-tyk-override-test": "tyk-override",
										"x-tyk-override-test-2": "tyk-override-2"
									}
								}
							}
						}
					]
				}
			}
		}
	},
	"proxy": {
		"listen_path": "/v1",
		"target_url": "` + testHttpAny + `"
	}
}`

func TestExtendedBlacklistLinks(t *testing.T) {
	uri := "v1/disallowed/blacklist/literal"
	req := testReq(t, "GET", uri, nil)
	req.Header.Set("version", "v1")

	spec := createDefinitionFromString(nonExpiringExtendedDefNoWhitelist)

	ok, status, _ := spec.IsRequestValid(req)
	if ok {
		t.Error("Request should fail as URL is blacklisted!")
	}

	if status != EndPointNotAllowed {
		t.Error("Request should return endpoint disallowed status!")
		t.Error(status)
	}

	uri = "v1/disallowed/blacklist/abacab12345"
	req = testReq(t, "GET", uri, nil)
	req.Header.Set("version", "v1")

	ok, status, _ = spec.IsRequestValid(req)
	if ok {
		t.Error("Request should fail as URL (with dynamic ID) is blacklisted!")
	}

	if status != EndPointNotAllowed {
		t.Error("Request should return endpoint disallowed status for regex blacklists too!")
		t.Error(status)
	}

	// Test with POST (it's a GET, should pass through)
	uri = "v1/disallowed/blacklist/abacab12345"
	req = testReq(t, "POST", uri, nil)
	req.Header.Set("version", "v1")

	ok, status, _ = spec.IsRequestValid(req)
	if !ok {
		t.Error("Request should fail as URL (with dynamic ID) is blacklisted!")
	}

	if status != StatusOk {
		t.Error("Request should return endpoint disallowed status for regex blacklists too!")
		t.Error(status)
	}
}

func TestExtendedWhiteLIstLinks(t *testing.T) {
	uri := "v1/allowed/whitelist/literal"
	req := testReq(t, "GET", uri, nil)
	req.Header.Set("version", "v1")

	spec := createDefinitionFromString(nonExpiringExtendedDef)

	ok, status, _ := spec.IsRequestValid(req)
	if !ok {
		t.Error("Request should be OK as URL is whitelisted!")
	}

	if status != StatusOk {
		t.Error("Request should return StatusOk!")
		t.Error(status)
	}

	uri = "v1/allowed/whitelist/12345abans"
	req = testReq(t, "GET", uri, nil)
	req.Header.Set("version", "v1")

	ok, status, _ = spec.IsRequestValid(req)
	if !ok {
		t.Error("Request should be OK as URL is whitelisted (regex)!")
	}

	if status != StatusOk {
		t.Error("Regex whitelist Request should return StatusOk!")
		t.Error(status)
	}
}

func TestExtendedWhiteListBlock(t *testing.T) {
	uri := "v1/allowed/bananaphone"
	req := testReq(t, "GET", uri, nil)
	req.Header.Set("version", "v1")

	spec := createDefinitionFromString(nonExpiringExtendedDef)

	ok, status, _ := spec.IsRequestValid(req)
	if ok {
		t.Error("Request should fail as things not in whitelist should be rejected!")
	}

	if status != EndPointNotAllowed {
		t.Error("Request should return EndPointNotAllowed!")
		t.Error(status)
	}
}

func TestExtendedIgnored(t *testing.T) {
	uri := "/v1/ignored/noregex"
	req := testReq(t, "GET", uri, nil)
	req.Header.Set("version", "v1")

	spec := createDefinitionFromString(nonExpiringExtendedDef)

	ok, status, _ := spec.IsRequestValid(req)
	if !ok {
		t.Error("Request should pass, URL is ignored")
	}

	if status != StatusOkAndIgnore {
		t.Error("Request should return StatusOkAndIgnore!")
		t.Error(status)
	}
}

func TestExtendedWhiteListWithRedirectedReply(t *testing.T) {
	uri := "v1/allowed/whitelist/reply/12345"
	req := testReq(t, "GET", uri, nil)
	req.Header.Set("version", "v1")

	spec := createDefinitionFromString(nonExpiringExtendedDef)

	ok, status, _ := spec.IsRequestValid(req)
	if !ok {
		t.Error("Request should be OK as URL is whitelisted! Status was: ", status)
	}

	if status != StatusRedirectFlowByReply {
		t.Error("Request should return StatusRedirectFlowByReply! Returned: ", status)
		t.Error(status)
	}
}

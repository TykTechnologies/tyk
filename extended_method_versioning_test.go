package main

import (
	"net/http"
	"net/url"
	"testing"
)

var nonExpiringExtendedDef string = `

	{
		"name": "Tyk Test API",
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
			"not_versioned": false,
			"versions": {
				"v1": {
					"name": "v1",
					"expires": "3000-01-02 15:04",
					"paths": {
						"ignored": [],
						"white_list": [],
						"black_list": []
					},
					"use_extended_paths": true,
					"extended_paths": {
						"ignored": [
							{
								"path": "/v1/ignored/noregex",
								"method_actions": {
									"GET": {
										"action": "no_action",
										"code": 200,
										"data": "",
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
										"data": "",
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
										"data": "",
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
										"data": "",
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
										"data": "",
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
										"data": "",
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
			"target_url": "http://lonelycode.com",
			"strip_listen_path": false
		}
	}

`

var nonExpiringExtendedDefNoWhitelist string = `

	{
		"name": "Tyk Test API",
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
			"not_versioned": false,
			"versions": {
				"v1": {
					"name": "v1",
					"expires": "3000-01-02 15:04",
					"paths": {
						"ignored": [],
						"white_list": [],
						"black_list": []
					},
					"use_extended_paths": true,
					"extended_paths": {
						"ignored": [
							{
								"path": "/v1/ignored/noregex",
								"method_actions": {
									"GET": {
										"action": "no_action",
										"code": 200,
										"data": "",
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
										"data": "",
										"headers": {
											"x-tyk-override-test": "tyk-override",
											"x-tyk-override-test-2": "tyk-override-2"
										}
									}
								}
							}
						],
						"white_list": [],
						"black_list": [
							{
								"path": "v1/disallowed/blacklist/literal",
								"method_actions": {
									"GET": {
										"action": "no_action",
										"code": 200,
										"data": "",
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
										"data": "",
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
			"target_url": "http://lonelycode.com",
			"strip_listen_path": false
		}
	}

`

func TestExtendedBlacklistLinks(t *testing.T) {
	uri := "v1/disallowed/blacklist/literal"
	method := "GET"
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("version", "v1")

	thisSpec := createDefinitionFromString(nonExpiringExtendedDefNoWhitelist)

	ok, status, _ := thisSpec.IsRequestValid(req)
	if ok {
		t.Error("Request should fail as URL is blacklisted!")
	}

	if status != EndPointNotAllowed {
		t.Error("Request should return endpoint disallowed status!")
		t.Error(status)
	}

	uri = "v1/disallowed/blacklist/abacab12345"
	method = "GET"
	param = make(url.Values)
	req, err = http.NewRequest(method, uri+param.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("version", "v1")

	ok, status, _ = thisSpec.IsRequestValid(req)
	if ok {
		t.Error("Request should fail as URL (with dynamic ID) is blacklisted!")
	}

	if status != EndPointNotAllowed {
		t.Error("Request should return endpoint disallowed status for regex blacklists too!")
		t.Error(status)
	}

	// Test wiht POST (it's a GET, should pass through)
	uri = "v1/disallowed/blacklist/abacab12345"
	method = "POST"
	param = make(url.Values)
	req, err = http.NewRequest(method, uri+param.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("version", "v1")

	ok, status, _ = thisSpec.IsRequestValid(req)
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
	method := "GET"
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("version", "v1")

	thisSpec := createDefinitionFromString(nonExpiringExtendedDef)

	ok, status, _ := thisSpec.IsRequestValid(req)
	if !ok {
		t.Error("Request should be OK as URL is whitelisted!")
	}

	if status != StatusOk {
		t.Error("Request should return StatusOk!")
		t.Error(status)
	}

	uri = "v1/allowed/whitelist/12345abans"
	method = "GET"
	param = make(url.Values)
	req, err = http.NewRequest(method, uri+param.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("version", "v1")

	ok, status, _ = thisSpec.IsRequestValid(req)
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
	method := "GET"
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("version", "v1")

	thisSpec := createDefinitionFromString(nonExpiringExtendedDef)

	ok, status, _ := thisSpec.IsRequestValid(req)
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
	method := "GET"
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("version", "v1")

	thisSpec := createDefinitionFromString(nonExpiringExtendedDef)

	ok, status, _ := thisSpec.IsRequestValid(req)
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
	method := "GET"
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("version", "v1")

	thisSpec := createDefinitionFromString(nonExpiringExtendedDef)

	ok, status, _ := thisSpec.IsRequestValid(req)
	if !ok {
		t.Error("Request should be OK as URL is whitelisted! Status was: ", status)
	}

	if status != StatusRedirectFlowByReply {
		t.Error("Request should return StatusRedirectFlowByReply! Returned: ", status)
		t.Error(status)
	}
}

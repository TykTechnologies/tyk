package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"

	"github.com/TykTechnologies/tykcommon"
)

var sampleDefiniton string = `

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
					"expires": "2006-01-02 15:04",
					"use_extended_paths": true,
					"paths": {
						"ignored": ["/v1/ignored/noregex", "/v1/ignored/with_id/{id}"],
						"white_list": ["v1/disallowed/blacklist/literal", "v1/disallowed/blacklist/{id}"],
						"black_list": ["v1/disallowed/whitelist/literal", "v1/disallowed/whitelist/{id}"]
					}
				}
			}
		},
		"proxy": {
			"listen_path": "/v1",
			"target_url": "http://example.com",
			"strip_listen_path": false
		}
	}

`

var nonExpiringDef string = `

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
						"ignored": ["/v1/ignored/noregex", "/v1/ignored/with_id/{id}"],
						"white_list": ["v1/allowed/whitelist/literal", "v1/allowed/whitelist/{id}"],
						"black_list": ["v1/disallowed/blacklist/literal", "v1/disallowed/blacklist/{id}"]
					}
				}
			}
		},
		"proxy": {
			"listen_path": "/v1",
			"target_url": "http://example.com",
			"strip_listen_path": false
		}
	}

`

var nonExpiringMultiDef string = `

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
						"ignored": ["/v1/ignored/noregex", "/v1/ignored/with_id/{id}"],
						"white_list": ["v1/allowed/whitelist/literal", "v1/allowed/whitelist/{id}"],
						"black_list": ["v1/disallowed/blacklist/literal", "v1/disallowed/blacklist/{id}"]
					}
				},
				"v2": {
					"name": "v2",
					"expires": "3000-01-02 15:04",
					"paths": {
						"ignored": ["/v1/ignored/noregex", "/v1/ignored/with_id/{id}"],
						"white_list": [],
						"black_list": ["v1/disallowed/blacklist/literal"]
					}
				}
			}
		},
		"proxy": {
			"listen_path": "/v1",
			"target_url": "http://example.com",
			"strip_listen_path": false
		}
	}

`

func createDefinitionFromString(defStr string) APISpec {
	var thisLoader = APIDefinitionLoader{}

	thisDef, thisRawDef := thisLoader.ParseDefinition([]byte(defStr))
	thisDef.RawData = thisRawDef
	thisSpec := thisLoader.MakeSpec(thisDef)
	thisSpec.APIDefinition = thisDef

	return thisSpec
}

func writeDefToFile(configStruct tykcommon.APIDefinition) {
	newConfig, err := json.Marshal(configStruct)
	if err != nil {
		log.Error("Problem marshalling configuration!")
		log.Error(err)
	} else {
		ioutil.WriteFile("app_sample.json", newConfig, 0644)
	}
}

func TestExpiredRequest(t *testing.T) {
	uri := "/v1/bananaphone"
	method := "GET"

	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.Header.Add("version", "v1")
	if err != nil {
		t.Fatal(err)
	}

	thisSpec := createDefinitionFromString(sampleDefiniton)

	ok, status, _ := thisSpec.IsRequestValid(req)
	if ok {
		t.Error("Request should fail as expiry date is in the past!")
	}

	if status != VersionExpired {
		t.Error("Request should return expired status!")
		t.Error(status)
	}
}

func TestNotVersioned(t *testing.T) {
	uri := "v1/allowed/whitelist/literal"
	method := "GET"

	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)

	if err != nil {
		t.Fatal(err)
	}

	thisSpec := createDefinitionFromString(nonExpiringDef)
	thisSpec.VersionData.NotVersioned = true

	//	writeDefToFile(thisSpec.APIDefinition)

	ok, status, _ := thisSpec.IsRequestValid(req)
	if ok != true {
		t.Error("Request should pass as versioning not in play!")
	}

	if status != StatusOk {
		t.Error("Request should return StatusOk status!")
		t.Error(status)
	}
}

func TestMissingVersion(t *testing.T) {
	uri := "/v1/bananaphone"
	method := "GET"

	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}

	thisSpec := createDefinitionFromString(sampleDefiniton)

	ok, status, _ := thisSpec.IsRequestValid(req)
	if ok == true {
		t.Error("Request should fail as there is no version number!")
	}

	if status != VersionNotFound {
		t.Error("Request should return version not found status!")
		t.Error(status)
	}
}

func TestWrongVersion(t *testing.T) {
	uri := "/v1/bananaphone"
	method := "GET"

	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("version", "v2")

	thisSpec := createDefinitionFromString(sampleDefiniton)

	ok, status, _ := thisSpec.IsRequestValid(req)
	if ok == true {
		t.Error("Request should fail as version number is wrong!")
	}

	if status != VersionDoesNotExist {
		t.Error("Request should return version doesn't exist status!")
		t.Error(status)
	}
}

func TestBlacklistLinks(t *testing.T) {
	uri := "v1/disallowed/blacklist/literal"
	method := "GET"
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("version", "v1")

	thisSpec := createDefinitionFromString(nonExpiringDef)

	ok, status, _ := thisSpec.IsRequestValid(req)
	if ok == true {
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
	if ok == true {
		t.Error("Request should fail as URL (with dynamic ID) is blacklisted!")
	}

	if status != EndPointNotAllowed {
		t.Error("Request should return endpoint disallowed status for regex blacklists too!")
		t.Error(status)
	}
}

func TestWhiteLIstLinks(t *testing.T) {
	uri := "v1/allowed/whitelist/literal"
	method := "GET"
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("version", "v1")

	thisSpec := createDefinitionFromString(nonExpiringDef)

	ok, status, _ := thisSpec.IsRequestValid(req)
	if ok != true {
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
	if ok != true {
		t.Error("Request should be OK as URL is whitelisted (regex)!")
	}

	if status != StatusOk {
		t.Error("Regex whitelist Request should return StatusOk!")
		t.Error(status)
	}
}

func TestWhiteListBlock(t *testing.T) {
	uri := "v1/allowed/bananaphone"
	method := "GET"
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("version", "v1")

	thisSpec := createDefinitionFromString(nonExpiringDef)

	ok, status, _ := thisSpec.IsRequestValid(req)
	if ok == true {
		t.Error("Request should fail as things not in whitelist should be rejected!")
	}

	if status != EndPointNotAllowed {
		t.Error("Request should return EndPointNotAllowed!")
		t.Error(status)
	}
}

func TestIgnored(t *testing.T) {
	uri := "/v1/ignored/noregex"
	method := "GET"
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("version", "v1")

	thisSpec := createDefinitionFromString(nonExpiringDef)

	ok, status, _ := thisSpec.IsRequestValid(req)
	if ok != true {
		t.Error("Request should pass, URL is ignored")
	}

	if status != StatusOkAndIgnore {
		t.Error("Request should return StatusOkAndIgnore!")
		t.Error(status)
	}
}

func TestBlacklistLinksMulti(t *testing.T) {
	uri := "v1/disallowed/blacklist/literal"
	method := "GET"
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("version", "v2")

	thisSpec := createDefinitionFromString(nonExpiringMultiDef)

	ok, status, _ := thisSpec.IsRequestValid(req)
	if ok == true {
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
	req.Header.Add("version", "v2")

	ok, status, _ = thisSpec.IsRequestValid(req)
	if ok != true {
		t.Error("Request should be OK as in v2 this URL is not blacklisted")
		t.Error(thisSpec.RxPaths["v2"])
	}

	if status != StatusOk {
		t.Error("Request should return StatusOK as URL not blacklisted!")
		t.Error(status)
	}
}

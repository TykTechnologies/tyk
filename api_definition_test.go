package main

import (
	"testing"
	"net/url"
	"net/http"
	"encoding/json"
	"io/ioutil"
)

func createDefinition() ApiSpec {
	var thisDef = ApiDefinition{}
	var v1 = VersionInfo{}
	var thisSpec = ApiSpec{}
	var thisLoader = ApiDefinitionLoader{}

	thisDef.Name = "Test API"
	thisDef.VersionDefinition.Key = "version"
	thisDef.VersionDefinition.Location = "header"
	thisDef.VersionData.NotVersioned = false

	v1.Name = "v1"
	v1.Auth.AuthHeaderName = "authorization"
	v1.Expires = "2006-01-02 15:04" //TODO: Change this
	thisDef.Proxy.ListenPath = "/v1"
	thisDef.Proxy.TargetUrl = "http://lonelycode.com"
	v1.Paths.Ignored = []string{"/v1/ignored/noregex", "/v1/ignored/with_id/{id}"}
	v1.Paths.BlackList = []string{"v1/disallowed/blacklist/literal", "v1/disallowed/blacklist/{id}"}
	v1.Paths.WhiteList = []string{"v1/disallowed/whitelist/literal", "v1/disallowed/whitelist/{id}"}

	thisDef.VersionData.Versions = make(map[string]VersionInfo)
	thisDef.VersionData.Versions[v1.Name] = v1

	thisSpec.ApiDefinition = thisDef

	thisSpec.RxPaths = make(map[string][]UrlSpec)
	thisSpec.WhiteListEnabled = make(map[string]bool)

	pathSpecs, whiteListSpecs := thisLoader.getPathSpecs(v1)
	thisSpec.RxPaths[v1.Name] = pathSpecs

	thisSpec.WhiteListEnabled[v1.Name] = whiteListSpecs

	return thisSpec
}

func createNonExpiringDefinition() ApiSpec {
	var thisDef = ApiDefinition{}
	var v1 = VersionInfo{}
	var thisSpec = ApiSpec{}
	var thisLoader = ApiDefinitionLoader{}

	thisDef.Name = "Test API"
	thisDef.VersionDefinition.Key = "version"
	thisDef.VersionDefinition.Location = "header"
	thisDef.VersionData.NotVersioned = false

	v1.Name = "v1"
	v1.Auth.AuthHeaderName = "authorization"
	v1.Expires = "3000-01-02 15:04" //TODO: Change this
	thisDef.Proxy.ListenPath = "/v1"
	thisDef.Proxy.TargetUrl = "http://lonelycode.com"
	v1.Paths.Ignored = []string{"/v1/ignored/noregex", "/v1/ignored/with_id/{id}"}
	v1.Paths.BlackList = []string{"v1/disallowed/blacklist/literal", "v1/disallowed/blacklist/{id}"}
	v1.Paths.WhiteList = []string{"v1/allowed/whitelist/literal", "v1/allowed/whitelist/{id}"}

	thisDef.VersionData.Versions = make(map[string]VersionInfo)
	thisDef.VersionData.Versions[v1.Name] = v1

	thisSpec.ApiDefinition = thisDef

	thisSpec.RxPaths = make(map[string][]UrlSpec)
	thisSpec.WhiteListEnabled = make(map[string]bool)

	pathSpecs, whiteListSpecs := thisLoader.getPathSpecs(v1)
	thisSpec.RxPaths[v1.Name] = pathSpecs

	thisSpec.WhiteListEnabled[v1.Name] = whiteListSpecs

	return thisSpec
}

func writeDefToFile(configStruct ApiDefinition) {
	newConfig, err := json.Marshal(configStruct)
	if err != nil {
		log.Error("Problem marshalling configuration!")
		log.Error(err)
	} else {
		ioutil.WriteFile("app_sample.json", newConfig, 0644)
	}
}

func createNonExpiringMultiDefinition() ApiSpec {
	var thisDef = ApiDefinition{}
	var v1 = VersionInfo{}
	var v2 = VersionInfo{}
	var thisSpec = ApiSpec{}
	var thisLoader = ApiDefinitionLoader{}

	thisDef.Name = "Test API"
	thisDef.VersionDefinition.Key = "version"
	thisDef.VersionDefinition.Location = "header"
	thisDef.VersionData.NotVersioned = false

	v1.Name = "v1"
	v1.Auth.AuthHeaderName = "authorization"
	v1.Expires = "3000-01-02 15:04"
	thisDef.Proxy.ListenPath = "/v1"
	thisDef.Proxy.TargetUrl = "http://lonelycode.com"
	v1.Paths.Ignored = []string{"/v1/ignored/noregex", "/v1/ignored/with_id/{id}"}
	v1.Paths.BlackList = []string{"v1/disallowed/blacklist/literal", "v1/disallowed/blacklist/{id}"}
	v1.Paths.WhiteList = []string{"v1/allowed/whitelist/literal", "v1/allowed/whitelist/{id}"}

	v2.Name = "v2"
	v2.Auth.AuthHeaderName = "authorization"
	v2.Expires = "3000-01-02 15:04"
	thisDef.Proxy.ListenPath = "/v2"
	thisDef.Proxy.TargetUrl = "http://lonelycode.com"
	v2.Paths.Ignored = []string{"/v1/ignored/noregex", "/v1/ignored/with_id/{id}"}
	v2.Paths.BlackList = []string{"v1/disallowed/blacklist/literal"}
	v2.Paths.WhiteList = []string{}

	thisDef.VersionData.Versions = make(map[string]VersionInfo)
	thisDef.VersionData.Versions[v1.Name] = v1
	thisDef.VersionData.Versions[v2.Name] = v2

	thisSpec.ApiDefinition = thisDef

	thisSpec.RxPaths = make(map[string][]UrlSpec)
	thisSpec.WhiteListEnabled = make(map[string]bool)

	pathSpecs, whiteListSpecs := thisLoader.getPathSpecs(v1)
	pathSpecs2, whiteListSpecs2 := thisLoader.getPathSpecs(v2)

	thisSpec.RxPaths[v1.Name] = pathSpecs
	thisSpec.WhiteListEnabled[v1.Name] = whiteListSpecs

	thisSpec.RxPaths[v2.Name] = pathSpecs2
	thisSpec.WhiteListEnabled[v2.Name] = whiteListSpecs2

	return thisSpec
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

	thisSpec := createDefinition()

	ok, status := thisSpec.IsRequestValid(req)
	if ok == true {
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

	thisSpec := createNonExpiringDefinition()
	thisSpec.VersionData.NotVersioned = true

	writeDefToFile(thisSpec.ApiDefinition)

	ok, status := thisSpec.IsRequestValid(req)
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

	thisSpec := createDefinition()

	ok, status := thisSpec.IsRequestValid(req)
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

	thisSpec := createDefinition()

	ok, status := thisSpec.IsRequestValid(req)
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

	thisSpec := createNonExpiringDefinition()

	ok, status := thisSpec.IsRequestValid(req)
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

	ok, status = thisSpec.IsRequestValid(req)
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

	thisSpec := createNonExpiringDefinition()

	ok, status := thisSpec.IsRequestValid(req)
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

	ok, status = thisSpec.IsRequestValid(req)
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

	thisSpec := createNonExpiringDefinition()

	ok, status := thisSpec.IsRequestValid(req)
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

	thisSpec := createNonExpiringDefinition()

	ok, status := thisSpec.IsRequestValid(req)
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

	thisSpec := createNonExpiringMultiDefinition()

	ok, status := thisSpec.IsRequestValid(req)
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

	ok, status = thisSpec.IsRequestValid(req)
	if ok != true {
		t.Error("Request should be OK as in v2 this URL is not blacklisted")
		t.Error(thisSpec.RxPaths["v2"])
	}

	if status != StatusOk {
		t.Error("Request should return StatusOK as URL not blacklisted!")
		t.Error(status)
	}
}

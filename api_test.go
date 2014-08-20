package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

var testDef string = `

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
				"Default": {
					"name": "Default",
					"expires": "3006-01-02 15:04",
					"paths": {
						"ignored": [],
						"white_list": [],
						"black_list": []
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

func MakeSampleAPI() *APISpec {
	thisSpec := createDefinitionFromString(testDef)
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	thisSpec.Init(&redisStore, &redisStore)
	ReloadURLStructure()

	return &thisSpec
}

type Success struct {
	Key    string `json:"key"`
	Status string `json:"status"`
	Action string `json:"action"`
}

func TestKeyHandlerNewKey(t *testing.T) {
	uri := "/tyk/keys/1234"
	method := "POST"
	sampleKey := createSampleSession()
	body, _ := json.Marshal(&sampleKey)

	recorder := httptest.NewRecorder()
	param := make(url.Values)

	MakeSampleAPI()
	param.Set("api_id", "1")
	req, err := http.NewRequest(method, uri+param.Encode(), strings.NewReader(string(body)))

	if err != nil {
		t.Fatal(err)
	}

	keyHandler(recorder, req)

	newSuccess := Success{}
	err = json.Unmarshal([]byte(recorder.Body.String()), &newSuccess)

	if err != nil {
		t.Error("Could not unmarshal success message:\n", err)
	} else {
		if newSuccess.Status != "ok" {
			t.Error("key not created, status error:\n", recorder.Body.String())
		}
		if newSuccess.Action != "added" {
			t.Error("Response is incorrect - action is not 'added' :\n", recorder.Body.String())
		}
	}
}

func TestKeyHandlerUpdateKey(t *testing.T) {
	uri := "/tyk/keys/1234"
	method := "PUT"
	sampleKey := createSampleSession()
	body, _ := json.Marshal(&sampleKey)

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	MakeSampleAPI()
	param.Set("api_id", "1")
	req, err := http.NewRequest(method, uri+param.Encode(), strings.NewReader(string(body)))

	if err != nil {
		t.Fatal(err)
	}

	keyHandler(recorder, req)

	newSuccess := Success{}
	err = json.Unmarshal([]byte(recorder.Body.String()), &newSuccess)

	if err != nil {
		t.Error("Could not unmarshal success message:\n", err)
	} else {
		if newSuccess.Status != "ok" {
			t.Error("key not created, status error:\n", recorder.Body.String())
		}
		if newSuccess.Action != "modified" {
			t.Error("Response is incorrect - action is not 'modified' :\n", recorder.Body.String())
		}
	}
}

func createKey() {
	uri := "/tyk/keys/1234"
	method := "POST"
	sampleKey := createSampleSession()
	body, _ := json.Marshal(&sampleKey)

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, _ := http.NewRequest(method, uri+param.Encode(), strings.NewReader(string(body)))

	keyHandler(recorder, req)
}

func TestKeyHandlerDeleteKey(t *testing.T) {
	createKey()

	uri := "/tyk/keys/1234?"
	method := "DELETE"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	MakeSampleAPI()
	param.Set("api_id", "1")
	req, err := http.NewRequest(method, uri+param.Encode(), nil)

	if err != nil {
		t.Fatal(err)
	}

	keyHandler(recorder, req)

	newSuccess := Success{}
	err = json.Unmarshal([]byte(recorder.Body.String()), &newSuccess)

	if err != nil {
		t.Error("Could not unmarshal success message:\n", err)
	} else {
		if newSuccess.Status != "ok" {
			t.Error("key not deleted, status error:\n", recorder.Body.String())
		}
		if newSuccess.Action != "deleted" {
			t.Error("Response is incorrect - action is not 'deleted' :\n", recorder.Body.String())
		}
	}
}

func TestCreateKeyHandlerCreateNewKey(t *testing.T) {
	createKey()

	uri := "/tyk/keys/create"
	method := "POST"

	sampleKey := createSampleSession()
	body, _ := json.Marshal(&sampleKey)

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	MakeSampleAPI()
	param.Set("api_id", "1")
	req, err := http.NewRequest(method, uri+param.Encode(), strings.NewReader(string(body)))

	if err != nil {
		t.Fatal(err)
	}

	createKeyHandler(recorder, req)

	newSuccess := Success{}
	err = json.Unmarshal([]byte(recorder.Body.String()), &newSuccess)

	if err != nil {
		t.Error("Could not unmarshal success message:\n", err)
	} else {
		if newSuccess.Status != "ok" {
			t.Error("key not created, status error:\n", recorder.Body.String())
		}
		if newSuccess.Action != "create" {
			t.Error("Response is incorrect - action is not 'create' :\n", recorder.Body.String())
		}
	}
}

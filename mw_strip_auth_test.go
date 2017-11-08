package main

import (
	"net/http"
	"testing"
)

var authedDef string = `
  {
		"name": "Tyk Auth Key Test",
		"api_id": "99898",
		"org_id": "default",
        "use_keyless": false,
		"definition": {
			"location": "header",
			"key": "version"
		},
		"auth": {
			"auth_header_name": "token",
            "use_param": true,
            "param_name": "q_auth"
		},
		"version_data": {
			"not_versioned": true,
			"versions": {
				"Default": {
					"name": "Default",
					"use_extended_paths": true,
					"expires": "3000-01-02 15:04",
					"paths": {
						"ignored": [],
						"white_list": [],
						"black_list": []
					}
				}
			}
		},
		"proxy": {
			"listen_path": "/auth_key_test/",
			"target_url": "http://example.com/",
			"strip_listen_path": true
		}
	}`

func TestStripAuth(t *testing.T) {
	spec := setUp(authedDef)
	mw := MWStripAuthData{}

	r, _ := http.NewRequest("GET", "http://example.com/?q_auth=foo&bar=baz", nil)
	r.Header.Add("token", "bar")
	mw.StripAuth(r, spec)

	if r.Header.Get("token") != "" {
		t.Fatal("request still had auth header")
	}

	if r.URL.Query().Get("q_name") != "" {
		t.Fatal("request still had auth query string")
	}

	if r.URL.String() != "http://example.com/?bar=baz" {
		t.Fatalf("URL is unexpected: %v\n", r.URL.String())
	}
}

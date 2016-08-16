// +build coprocess

package main

import(
  "net/http"
  "net/http/httptest"
  "testing"
)

var basicCoProcessPreDef string = `

	{
		"name": "Tyk Test API - IPCONF Fail",
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
			"not_versioned": true,
			"versions": {
				"v1": {
					"name": "v1",
					"expires": "2100-01-02 15:04",
					"use_extended_paths": true,
					"paths": {
						"ignored": [],
						"white_list": [],
						"black_list": []
					}
				}
			}
		},
    "custom_middleware": {
      "pre": [
        {
          "name": "SomePreHandler",
          "require_session": false
        }
      ],
      "driver": "python"
    },
		"proxy": {
			"listen_path": "/v1",
			"target_url": "http://izumi.tykbeta.com",
			"strip_listen_path": false
		}
	}
`

var basicCoProcessOttoDef string = `

	{
		"name": "Tyk Test API - IPCONF Fail",
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
			"not_versioned": true,
			"versions": {
				"v1": {
					"name": "v1",
					"expires": "2100-01-02 15:04",
					"use_extended_paths": true,
					"paths": {
						"ignored": [],
						"white_list": [],
						"black_list": []
					}
				}
			}
		},
    "custom_middleware": {
      "pre": [
        {
          "name": "samplePreProcessMiddleware",
          "path": "middleware/sample_pre.js",
          "require_session": false
        }
      ]
    },
		"proxy": {
			"listen_path": "/v1",
			"target_url": "http://izumi.tykbeta.com",
			"strip_listen_path": false
		}
	}
`


func MakeCoProcessSampleAPI(apiTestDef string) *APISpec {
	log.Debug("CREATING TEMPORARY API FOR IP WHITELIST")
	thisSpec := createDefinitionFromString(apiTestDef)
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	thisSpec.Init(&redisStore, &redisStore, healthStore, orgStore)
	return &thisSpec
}

func TestCoProcessMiddleware(t *testing.T) {
  spec := MakeCoProcessSampleAPI(basicCoProcessPreDef)

  thisSession := createNonThrottledSession()
  spec.SessionManager.UpdateSession("abc", thisSession, 60)

  uri := "/headers"
  method := "GET"

  recorder := httptest.NewRecorder()

  req, err := http.NewRequest(method, uri, nil)
  req.Header.Add("authorization", "abc")

  if err != nil {
    t.Fatal(err)
  }

  chain := getChain(*spec)
  chain.ServeHTTP(recorder, req)

  if recorder.Code != 200 {
    t.Error("Invalid response code, should be 200:  \n", recorder.Code, recorder.Body, req.RemoteAddr)
  }
}

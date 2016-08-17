// +build coprocess

package main

import(
  "net/http"
  "net/http/httptest"
  "io/ioutil"
  "path"
  "os"
  "strings"
  "testing"
  "bytes"
  "net/url"

  "github.com/justinas/alice"

  "github.com/TykTechnologies/tykcommon"
  "github.com/TykTechnologies/tyk/coprocess"

  "github.com/TykTechnologies/tyk/coprocess/test"
)

const(
  baseMiddlewarePath = "middleware/python"
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
          "name": "MyPreMiddleware",
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

var pythonTestPreMiddleware string = `
from tyk.decorators import *
from gateway import TykGateway as tyk

@Pre
def MyPreMiddleware(request, session, spec):
    print("my_middleware: MyPreMiddleware")
    return request, session
`

var _ = writeTestMiddleware("cp_test_test_middleware.py", pythonTestPreMiddleware)

var TestDispatcher, _ = coprocess_test.NewTestDispatcher()

func writeTestMiddleware(filename string, testMiddleware string) bool {
  middlewarePath := path.Join("middleware/python", filename)
  ioutil.WriteFile(middlewarePath, []byte(testMiddleware), 0644)
  return true
}

func removeTestMiddlewares() {
  files , _ := ioutil.ReadDir(baseMiddlewarePath)
  for _, f := range files {
    isTestMiddleware := strings.Index(f.Name(), "cp_test")
    middlewarePath := path.Join(baseMiddlewarePath, f.Name())

    if isTestMiddleware == 0 {
      os.Remove(middlewarePath)
    }
  }
}

func getCoProcessChain(spec APISpec, hookName string, hookType coprocess.HookType, driver tykcommon.MiddlewareDriver) http.Handler {
	remote, _ := url.Parse(spec.Proxy.TargetURL)
	proxy := TykNewSingleHostReverseProxy(remote, &spec)
	proxyHandler := http.HandlerFunc(ProxyHandler(proxy, &spec))
	tykMiddleware := &TykMiddleware{&spec, proxy}
	chain := alice.New(
    CreateCoProcessMiddleware(hookName, hookType, driver, tykMiddleware),
		CreateMiddleware(&IPWhiteListMiddleware{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&AuthKey{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&VersionCheck{TykMiddleware: tykMiddleware}, tykMiddleware),
		CreateMiddleware(&KeyExpired{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&AccessRightsCheck{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&RateLimitAndQuotaCheck{tykMiddleware}, tykMiddleware)).Then(proxyHandler)

	return chain
}

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

  writeTestMiddleware("cp_test_test_middleware.py", pythonTestPreMiddleware)

  spec := MakeCoProcessSampleAPI(basicCoProcessPreDef)

  thisSession := createNonThrottledSession()
  spec.SessionManager.UpdateSession("abc", thisSession, 60)

  uri := "/headers"
  method := "GET"

  recorder := httptest.NewRecorder()

  param := make(url.Values)

  req, err := http.NewRequest(method, uri,  bytes.NewBufferString(param.Encode()) )
  req.Header.Add("authorization", "abc")

  if err != nil {
    t.Fatal(err)
  }

  chain := getCoProcessChain(*spec, "abc", coprocess.HookType_Pre, "python")

  chain.ServeHTTP(recorder, req)

  if recorder.Code != 200 {
    t.Error("Invalid response code, should be 200:  \n", recorder.Code, recorder.Body, req.RemoteAddr)
  }

  removeTestMiddlewares()
}

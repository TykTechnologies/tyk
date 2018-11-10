// +build !race

// Looping by itself has race nature
package main

import (
	"encoding/json"
	"sync"
	"testing"

	"github.com/TykTechnologies/tyk/test"
)

func TestLooping(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	postAction := `<operation action="https://example.com/post_action">data</operation>`
	getAction := `<operation action="https://example.com/get_action">data</operation>`

	t.Run("Using advanced URL rewrite", func(t *testing.T) {
		// We defined internnal advanced rewrite based on body data
		// which rewrites to internal paths (marked as blacklist so they protected from outside world)
		buildAndLoadAPI(func(spec *APISpec) {
			version := spec.VersionData.Versions["v1"]
			json.Unmarshal([]byte(`{
                "use_extended_paths": true,
                "extended_paths": {
                    "url_rewrites": [{
                        "path": "/xml",
                        "method": "POST",
                        "match_pattern": "/xml(.*)",
                        "rewrite_to": "/xml$1",
                        "triggers": [
                          {
                            "on": "all",
                            "options": {
                              "payload_matches": {
                                "match_rx": "post_action"
                              }
                            },
                            "rewrite_to": "tyk://self/post_action"
                          },
                          {
                            "on": "all",
                            "options": {
                              "payload_matches": {
                                "match_rx": "get_action"
                              }
                            },
                            "rewrite_to": "tyk://self/get_action?method=GET"
                          }
                        ]
                    }]
                }
            }`), &version)

			spec.VersionData.Versions["v1"] = version

			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			{Method: "POST", Path: "/xml", Data: postAction, BodyMatch: `"Url":"/post_action`},

			// Should retain original query params
			{Method: "POST", Path: "/xml?a=b", Data: getAction, BodyMatch: `"Url":"/get_action`},

			// Should rewrite http method, if loop rewrite param passed
			{Method: "POST", Path: "/xml", Data: getAction, BodyMatch: `"Method":"GET"`},
		}...)
	})

	t.Run("VirtualEndpoint or plugins", func(t *testing.T) {
		testPrepareVirtualEndpoint(`
            function testVirtData(request, session, config) {
                var loopLocation = "/default"

                if (request.Body.match("post_action")) {
                    loopLocation = "tyk://self/post_action"
                } else if (request.Body.match("get_action")) {
                    loopLocation = "tyk://self/get_action?method=GET"
                }

                var resp = {
                    Headers: {
                        "Location": loopLocation,
                    },
                    Code: 302
                }
                return TykJsResponse(resp, session.meta_data)
            }
        `, "POST", "/virt", true)

		ts.Run(t, []test.TestCase{
			{Method: "POST", Path: "/virt", Data: postAction, BodyMatch: `"Url":"/post_action`},

			// Should retain original query params
			{Method: "POST", Path: "/virt?a=b", Data: getAction, BodyMatch: `"Url":"/get_action`},

			// Should rewrite http method, if loop rewrite param passed
			{Method: "POST", Path: "/virt", Data: getAction, BodyMatch: `"Method":"GET"`},
		}...)
	})

	t.Run("Loop limit", func(t *testing.T) {
		buildAndLoadAPI(func(spec *APISpec) {
			version := spec.VersionData.Versions["v1"]
			json.Unmarshal([]byte(`{
                "use_extended_paths": true,
                "extended_paths": {
                    "url_rewrites": [{
                        "path": "/recursion",
                        "match_pattern": "/recursion(.*)",
                        "method": "GET",
                        "rewrite_to": "tyk://self/recursion?loop_limit=2"
                    }]
                }
            }`), &version)

			spec.VersionData.Versions["v1"] = version
			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			{Method: "GET", Path: "/recursion", Code: 500, BodyMatch: "Loop level too deep. Found more than 2 loops in single request"},
		}...)
	})
}

func TestConcurrencyReloads(t *testing.T) {
	var wg sync.WaitGroup

	ts := newTykTestServer()
	defer ts.Close()

	buildAndLoadAPI()

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			ts.Run(t, test.TestCase{Path: "/sample", Code: 200})
			wg.Done()
		}()
	}

	for j := 0; j < 5; j++ {
		buildAndLoadAPI()
	}

	wg.Wait()
}

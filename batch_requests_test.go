package main

import (
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/TykTechnologies/tyk/test"
)

const testBatchRequest = `{
	"requests": [
	{
		"method": "GET",
		"headers": {
			"test-header-1": "test-1",
			"test-header-2": "test-2"
		},
		"relative_url": "get/?param1=this"
	},
	{
		"method": "POST",
		"body": "TEST BODY",
		"relative_url": "post/"
	},
	{
		"method": "PUT",
		"relative_url": "put/"
	}
	],
	"suppress_parallel_execution": true
}`

func TestBatch(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	buildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/v1/"
		spec.EnableBatchRequestSupport = true
	})

	ts.Run(t, []test.TestCase{
		{Method: "POST", Path: "/v1/tyk/batch/", Data: `{"requests":[]}`, Code: 200, BodyMatch: "[]"},
		{Method: "POST", Path: "/v1/tyk/batch/", Data: "malformed", Code: 400},
		{Method: "POST", Path: "/v1/tyk/batch/", Data: testBatchRequest, Code: 200},
	}...)

	resp, _ := ts.Do(test.TestCase{Method: "POST", Path: "/v1/tyk/batch/", Data: testBatchRequest})
	if resp != nil {
		body, _ := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()

		var batchResponse []map[string]json.RawMessage
		if err := json.Unmarshal(body, &batchResponse); err != nil {
			t.Fatal(err)
		}

		if len(batchResponse) != 3 {
			t.Errorf("Length not match: %d", len(batchResponse))
		}

		if string(batchResponse[0]["relative_url"]) != `"get/?param1=this"` {
			t.Error("Url order not match:", string(batchResponse[0]["relative_url"]))
		}
	}
}

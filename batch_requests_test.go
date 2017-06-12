package main

import (
	"testing"
)

const batchTestDef = `{
	"api_id": "987999",
	"org_id": "default",
	"auth": {
		"auth_header_name": "authorization"
	},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"Default": {
				"name": "Default"
			}
		}
	},
	"proxy": {
		"listen_path": "/v1/",
		"target_url": "` + testHttpAny + `"
	},
	"enable_batch_request_support": true
}`

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

func TestBatchSuccess(t *testing.T) {
	spec := createSpecTest(t, batchTestDef)

	batchHandler := BatchRequestHandler{API: spec}

	req := testReq(t, "POST", "/vi/tyk/batch/", testBatchRequest)

	// Test decode
	batchRequest, err := batchHandler.DecodeBatchRequest(req)
	if err != nil {
		t.Error("Decode batch request body failed: ", err)
	}

	if len(batchRequest.Requests) != 3 {
		t.Error("Decoded batchRequest object doesn;t have the right number of requests, should be 3, is: ", len(batchRequest.Requests))
	}

	if !batchRequest.SuppressParallelExecution {
		t.Error("Parallel execution flag should be True, is: ", batchRequest.SuppressParallelExecution)
	}

	// Test request constructions:

	requestSet, err := batchHandler.ConstructRequests(batchRequest, false)
	if err != nil {
		t.Error("Batch request creation failed , request structure malformed")
	}

	if len(requestSet) != 3 {
		t.Error("Request set length should be 3, is: ", len(requestSet))
	}

	if requestSet[0].URL.Host != "localhost:8080" {
		t.Error("Request Host is wrong, is: ", requestSet[0].URL.Host)
	}

	if requestSet[0].URL.Path != "/v1/get/" {
		t.Error("Request Path is wrong, is: ", requestSet[0].URL.Path)
	}

}

func TestMakeSyncRequest(t *testing.T) {
	spec := createSpecTest(t, batchTestDef)
	batchHandler := BatchRequestHandler{API: spec}

	relURL := "/"
	req := testReq(t, "GET", testHttpGet, nil)

	replyUnit := batchHandler.doSyncRequest(req, relURL)

	if replyUnit.RelativeURL != relURL {
		t.Error("Relativce URL in reply is wrong")
	}
	if replyUnit.Code != 200 {
		t.Error("Response reported a non-200 response")
	}
	if len(replyUnit.Body) < 1 {
		t.Error("Reply body is too short, should be larger than 1!")
	}
}

func TestMakeASyncRequest(t *testing.T) {
	spec := createSpecTest(t, batchTestDef)
	batchHandler := BatchRequestHandler{API: spec}

	relURL := "/"
	req := testReq(t, "GET", testHttpGet, nil)

	replies := make(chan BatchReplyUnit)
	go batchHandler.doAsyncRequest(req, relURL, replies)
	replyUnit := BatchReplyUnit{}
	replyUnit = <-replies

	if replyUnit.RelativeURL != relURL {
		t.Error("Relativce URL in reply is wrong")
	}
	if replyUnit.Code != 200 {
		t.Error("Response reported a non-200 response")
	}
	if len(replyUnit.Body) < 1 {
		t.Error("Reply body is too short, should be larger than 1!")
	}
}

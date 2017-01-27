package main

import (
	"net/http"
	"strings"
	"testing"
)

var batchTestDef = `

	{
		"name": "Tyk Test API",
		"api_id": "987999",
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
				"Default": {
					"name": "Default",
					"expires": "3000-01-02 15:04",
					"use_extended_paths": true,
					"paths": {
						"ignored": [],
						"black_list": [],
						"white_list": []
					}
				}
			}
		},
		"event_handlers": {
			"events": {}
		},
		"proxy": {
			"listen_path": "/v1/",
			"target_url": "http://httpbin.org",
			"strip_listen_path": true
		},
		"enable_batch_request_support": true
	}

`

var testBatchRequest = `

{
	"requests": [
	{
		"method": "GET",
		"headers": {
			"test-header-1": "test-1",
			"test-header-2": "test-2"
		},
		"body": "",
		"relative_url": "get/?param1=this"
	},
	{
		"method": "POST",
		"headers": {},
		"body": "TEST BODY",
		"relative_url": "post/"
	},
	{
		"method": "PUT",
		"headers": {},
		"body": "",
		"relative_url": "put/"
	}
	],
	"suppress_parallel_execution": true
}

`

func TestBatchSuccess(t *testing.T) {
	spec := createDefinitionFromString(batchTestDef)
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)

	batchHandler := BatchRequestHandler{API: spec}

	r, _ := http.NewRequest("POST", "/vi/tyk/batch/", strings.NewReader(testBatchRequest))

	// Test decode
	batchRequest, decodeErr := batchHandler.DecodeBatchRequest(r)
	if decodeErr != nil {
		t.Error("Decode batch request body failed: ", decodeErr)
	}

	if len(batchRequest.Requests) != 3 {
		t.Error("Decoded batchRequest object doesn;t have the right number of requests, should be 3, is: ", len(batchRequest.Requests))
	}

	if !batchRequest.SuppressParallelExecution {
		t.Error("Parallel execution flag should be True, is: ", batchRequest.SuppressParallelExecution)
	}

	// Test request constructions:

	requestSet, createReqErr := batchHandler.ConstructRequests(batchRequest, false)
	if createReqErr != nil {
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
	spec := createDefinitionFromString(batchTestDef)
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)

	batchHandler := BatchRequestHandler{API: spec}

	relURL := "/"
	thisRequest, _ := http.NewRequest("GET", "http://example.com/", nil)

	replyUnit := batchHandler.doSyncRequest(thisRequest, relURL)

	if replyUnit.RelativeURL != relURL {
		t.Error("Relativce URL in reply is wrong")
	}

	if replyUnit.Code != 200 {
		t.Error("Repsonse reported a non-200 reponse (could be because lonelycode.com is down)")
	}

	if len(replyUnit.Body) < 1 {
		t.Error("Reply body is too short, should be larger than 1!")
	}

}

func TestMakeASyncRequest(t *testing.T) {
	spec := createDefinitionFromString(batchTestDef)
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)

	batchHandler := BatchRequestHandler{API: spec}

	relURL := "/"
	thisRequest, _ := http.NewRequest("GET", "http://example.com/", nil)

	replies := make(chan BatchReplyUnit)
	go batchHandler.doAsyncRequest(thisRequest, relURL, replies)
	replyUnit := BatchReplyUnit{}
	replyUnit = <-replies

	if replyUnit.RelativeURL != relURL {
		t.Error("Relativce URL in reply is wrong")
	}

	if replyUnit.Code != 200 {
		t.Error("Repsonse reported a non-200 reponse (could be because http://example.com/ is down)")
	}

	if len(replyUnit.Body) < 1 {
		t.Error("Reply body is too short, should be larger than 1!")
	}

}

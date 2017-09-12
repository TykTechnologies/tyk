package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

// RequestDefinition defines a batch request
type RequestDefinition struct {
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	RelativeURL string            `json:"relative_url"`
}

// BatchRequestStructure defines a batch request order
type BatchRequestStructure struct {
	Requests                  []RequestDefinition `json:"requests"`
	SuppressParallelExecution bool                `json:"suppress_parallel_execution"`
}

// BatchReplyUnit encodes a request suitable for replying to a batch request
type BatchReplyUnit struct {
	RelativeURL string      `json:"relative_url"`
	Code        int         `json:"code"`
	Headers     http.Header `json:"headers"`
	Body        string      `json:"body"`
}

// BatchRequestHandler handles batch requests on /tyk/batch for any API Definition that has the feature enabled
type BatchRequestHandler struct {
	API *APISpec
}

// doAsyncRequest runs an async request and replies to a channel
func (b *BatchRequestHandler) doAsyncRequest(req *http.Request, relURL string, out chan BatchReplyUnit) {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error("Webhook request failed: ", err)
		return
	}

	defer resp.Body.Close()
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Warning("Body read failure! ", err)
		return
	}

	out <- BatchReplyUnit{
		RelativeURL: relURL,
		Code:        resp.StatusCode,
		Headers:     resp.Header,
		Body:        string(content),
	}
}

// doSyncRequest will make the same request but return a BatchReplyUnit
func (b *BatchRequestHandler) doSyncRequest(req *http.Request, relURL string) BatchReplyUnit {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error("Webhook request failed: ", err)
		return BatchReplyUnit{}
	}

	defer resp.Body.Close()
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Warning("Body read failure! ", err)
		return BatchReplyUnit{}
	}

	return BatchReplyUnit{
		RelativeURL: relURL,
		Code:        resp.StatusCode,
		Headers:     resp.Header,
		Body:        string(content),
	}
}

func (b *BatchRequestHandler) DecodeBatchRequest(r *http.Request) (BatchRequestStructure, error) {
	var batchRequest BatchRequestStructure
	err := json.NewDecoder(r.Body).Decode(&batchRequest)
	return batchRequest, err
}

func (b *BatchRequestHandler) ConstructRequests(batchRequest BatchRequestStructure, unsafe bool) ([]*http.Request, error) {
	requestSet := []*http.Request{}

	for i, requestDef := range batchRequest.Requests {
		// We re-build the URL to ensure that the requested URL is actually for the API in question
		// URLs need to be built absolute so they go through the rate limiting and request limiting machinery
		var absURL string
		if !unsafe {
			absUrlHeader := "http://localhost:" + strconv.Itoa(globalConf.ListenPort)
			absURL = strings.Join([]string{absUrlHeader, strings.Trim(b.API.Proxy.ListenPath, "/"), requestDef.RelativeURL}, "/")
		} else {
			absURL = requestDef.RelativeURL
		}

		request, err := http.NewRequest(requestDef.Method, absURL, strings.NewReader(requestDef.Body))
		if err != nil {
			log.Error("Failure generating batch request for request spec index: ", i)
			return nil, err
		}

		// Add headers
		for k, v := range requestDef.Headers {
			request.Header.Set(k, v)
		}

		requestSet = append(requestSet, request)
	}

	return requestSet, nil
}

func (b *BatchRequestHandler) MakeRequests(batchRequest BatchRequestStructure, requestSet []*http.Request) []BatchReplyUnit {
	replySet := []BatchReplyUnit{}

	if len(batchRequest.Requests) != len(requestSet) {
		log.Error("Something went wrong creating requests, they are of mismatched lengths!", len(batchRequest.Requests), len(requestSet))
	}

	if !batchRequest.SuppressParallelExecution {
		replies := make(chan BatchReplyUnit)
		for index, req := range requestSet {
			go b.doAsyncRequest(req, batchRequest.Requests[index].RelativeURL, replies)
		}

		for range batchRequest.Requests {
			replySet = append(replySet, <-replies)
		}
	} else {
		for index, req := range requestSet {
			reply := b.doSyncRequest(req, batchRequest.Requests[index].RelativeURL)
			replySet = append(replySet, reply)
		}
	}

	return replySet
}

// HandleBatchRequest is the actual http handler for a batch request on an API definition
func (b *BatchRequestHandler) HandleBatchRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}

	// Decode request
	batchRequest, err := b.DecodeBatchRequest(r)
	if err != nil {
		log.Error("Could not decode batch request, decoding failed: ", err)
		doJSONWrite(w, 400, apiError("Batch request malformed"))
		return
	}

	// Construct the requests
	requestSet, err := b.ConstructRequests(batchRequest, false)
	if err != nil {
		doJSONWrite(w, 400, apiError(fmt.Sprintf("Batch request creation failed , request structure malformed")))
		return
	}

	// Run requests and collate responses
	replySet := b.MakeRequests(batchRequest, requestSet)

	// Respond
	doJSONWrite(w, 200, replySet)
}

// HandleBatchRequest is the actual http handler for a batch request on an API definition
func (b *BatchRequestHandler) ManualBatchRequest(requestObject []byte) []byte {

	// Decode request
	var batchRequest BatchRequestStructure
	if err := json.Unmarshal(requestObject, &batchRequest); err != nil {
		log.Error("Could not decode batch request, decoding failed: ", err)
		return nil
	}

	// Construct the unsafe requests
	requestSet, err := b.ConstructRequests(batchRequest, true)
	if err != nil {
		log.Error("Batch request creation failed , request structure malformed: ", err)
		return nil
	}

	// Run requests and collate responses
	replySet := b.MakeRequests(batchRequest, requestSet)

	// Encode responses
	replyMessage, err := json.Marshal(&replySet)
	if err != nil {
		log.Error("Couldn't encode response to string! ", err)
		return nil
	}

	return replyMessage
}

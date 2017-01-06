package main

import (
	"bytes"
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
func (b BatchRequestHandler) doAsyncRequest(req *http.Request, relURL string, out chan BatchReplyUnit) {
	client := &http.Client{}
	resp, doReqErr := client.Do(req)

	if doReqErr != nil {
		log.Error("Webhook request failed: ", doReqErr)
		return
	}

	defer resp.Body.Close()
	content, readErr := ioutil.ReadAll(resp.Body)
	if readErr != nil {
		log.Warning("Body read failure! ", readErr)
		return
	}

	reply := BatchReplyUnit{
		RelativeURL: relURL,
		Code:        resp.StatusCode,
		Headers:     resp.Header,
		Body:        string(content),
	}

	out <- reply

}

// doSyncRequest will make the same request but return a BatchReplyUnit
func (b BatchRequestHandler) doSyncRequest(req *http.Request, relURL string) BatchReplyUnit {
	client := &http.Client{}
	resp, doReqErr := client.Do(req)

	if doReqErr != nil {
		log.Error("Webhook request failed: ", doReqErr)
		return BatchReplyUnit{}
	}

	defer resp.Body.Close()
	content, readErr := ioutil.ReadAll(resp.Body)
	if readErr != nil {
		log.Warning("Body read failure! ", readErr)
		return BatchReplyUnit{}
	}

	reply := BatchReplyUnit{
		RelativeURL: relURL,
		Code:        resp.StatusCode,
		Headers:     resp.Header,
		Body:        string(content),
	}

	return reply
}

func (b BatchRequestHandler) DecodeBatchRequest(r *http.Request) (BatchRequestStructure, error) {
	decoder := json.NewDecoder(r.Body)
	var batchRequest BatchRequestStructure
	decodeErr := decoder.Decode(&batchRequest)

	return batchRequest, decodeErr
}

func (b BatchRequestHandler) ConstructRequests(batchRequest BatchRequestStructure, unsafe bool) ([]*http.Request, error) {
	requestSet := []*http.Request{}

	for i, requestDef := range batchRequest.Requests {
		// We re-build the URL to ensure that the requested URL is actually for the API in question
		// URLs need to be built absolute so they go through the rate limiting and request limiting machinery
		var absURL string
		if !unsafe {
			absUrlHeader := strings.Join([]string{"http://localhost", strconv.Itoa(config.ListenPort)}, ":")
			absURL = strings.Join([]string{absUrlHeader, strings.Trim(b.API.Proxy.ListenPath, "/"), requestDef.RelativeURL}, "/")
		} else {
			absURL = requestDef.RelativeURL
		}

		thisRequest, createReqErr := http.NewRequest(requestDef.Method, absURL, bytes.NewBuffer([]byte(requestDef.Body)))
		if createReqErr != nil {
			log.Error("Failure generating batch request for request spec index: ", i)
			return nil, createReqErr
		}

		// Add headers
		for k, v := range requestDef.Headers {
			thisRequest.Header.Add(k, v)
		}

		requestSet = append(requestSet, thisRequest)
	}

	return requestSet, nil
}

func (b BatchRequestHandler) MakeRequests(batchRequest BatchRequestStructure, requestSet []*http.Request) []BatchReplyUnit {
	ReplySet := []BatchReplyUnit{}

	if len(batchRequest.Requests) != len(requestSet) {
		log.Error("Something went wrong creating requests, they are of mismatched lengths!", len(batchRequest.Requests), len(requestSet))
	}

	if !batchRequest.SuppressParallelExecution {
		replies := make(chan BatchReplyUnit)
		for index, req := range requestSet {
			go b.doAsyncRequest(req, batchRequest.Requests[index].RelativeURL, replies)
		}

		for i := 0; i < len(batchRequest.Requests); i++ {
			val := <-replies

			ReplySet = append(ReplySet, val)
		}
	} else {
		for index, req := range requestSet {
			reply := b.doSyncRequest(req, batchRequest.Requests[index].RelativeURL)
			ReplySet = append(ReplySet, reply)
		}
	}

	return ReplySet
}

// HandleBatchRequest is the actual http handler for a batch request on an API definition
func (b BatchRequestHandler) HandleBatchRequest(w http.ResponseWriter, r *http.Request) {

	if r.Method == "POST" {

		// Decode request
		batchRequest, decodeErr := b.DecodeBatchRequest(r)
		if decodeErr != nil {
			log.Error("Could not decode batch request, decoding failed: ", decodeErr)
			ReturnError("Batch request malformed", w)
			return
		}

		// Construct the requests
		requestSet, createReqErr := b.ConstructRequests(batchRequest, false)
		if createReqErr != nil {
			ReturnError(fmt.Sprintf("Batch request creation failed , request structure malformed"), w)
			return
		}

		// Run requests and collate responses
		ReplySet := b.MakeRequests(batchRequest, requestSet)

		// Encode responses
		replyMessage, encErr := json.Marshal(&ReplySet)
		if encErr != nil {
			log.Error("Couldn't encode response to string! ", encErr)
			return
		}

		// Respond
		DoJSONWrite(w, 200, replyMessage)
	}

}

// HandleBatchRequest is the actual http handler for a batch request on an API definition
func (b BatchRequestHandler) ManualBatchRequest(RequestObject []byte) []byte {

	// Decode request
	var batchRequest BatchRequestStructure
	decodeErr := json.Unmarshal(RequestObject, &batchRequest)

	if decodeErr != nil {
		log.Error("Could not decode batch request, decoding failed: ", decodeErr)
		return []byte{}
	}

	// Construct the unsafe requests
	requestSet, createReqErr := b.ConstructRequests(batchRequest, true)
	if createReqErr != nil {
		log.Error("Batch request creation failed , request structure malformed: ", createReqErr)
		return []byte{}
	}

	// Run requests and collate responses
	ReplySet := b.MakeRequests(batchRequest, requestSet)

	// Encode responses
	replyMessage, encErr := json.Marshal(&ReplySet)
	if encErr != nil {
		log.Error("Couldn't encode response to string! ", encErr)
		return []byte{}
	}

	return replyMessage

}

// ReturnError returns an error to the http response writer
func ReturnError(err string, w http.ResponseWriter) {
	replyMessage := createError(err)
	DoJSONWrite(w, 400, replyMessage)
}

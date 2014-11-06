package main

import (
	"net/http"
	"encoding/json"
	"bytes"
	"fmt"
	"io/ioutil"
	"strings"
	"strconv"
)

// RequestDefinition defines a batch request
type RequestDefinition struct {
	Method string	`json:"method"`
	Headers map[string]string 	`json:"headers"`
	Body string	`json:"body"`
	RelativeURL string 	`json:"relative_url"`
}

// BatchRequestStructure defines a batch request order
type BatchRequestStructure struct {
	Requests []RequestDefinition	`json:"requests"`
	SuppressParallelExecution bool	`json:"suppress_parallel_execution"`
}

// BatchReplyUnit encodes a request suitable for replying to a batch request
type BatchReplyUnit struct {
	RelativeURL string	`json:"relative_url"`
	Code int	`json:"code"`
	Headers http.Header	`json:"headers"`
	Body string	`json:"body"`
}

// BatchRequestHandler handles batch requests on /tyk/batch for any API Definition that has the feature enabled
type BatchRequestHandler struct {
	API        *APISpec
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
		Code: resp.StatusCode,
		Headers: resp.Header,
		Body: string(content),
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
		Code: resp.StatusCode,
		Headers: resp.Header,
		Body: string(content),
	}

	return reply
}

// HandleBatchRequest is the actual http handler for a batch request on an API definition
func (b BatchRequestHandler) HandleBatchRequest(w http.ResponseWriter, r *http.Request) {

	if r.Method == "POST" {
		decoder := json.NewDecoder(r.Body)
		var batchRequest BatchRequestStructure
		decodeErr := decoder.Decode(&batchRequest)

		if decodeErr != nil {
			log.Error("Could not decode batch request, decoding failed: ", decodeErr)
			ReturnError("Batch request malformed", w)
			return
		}

		// Construct the requests
		requestSet := []*http.Request{}

		for i, requestDef := range(batchRequest.Requests) {
			// We re-build the URL to ensure that the requested URL is actually for the API in question
			// URLs need to be built absolute so they go through the rate limiting and request limiting machinery
			absUrlHeader := strings.Join([]string{"http://localhost", strconv.Itoa(config.ListenPort)}, ":")
			absURL := strings.Join([]string{absUrlHeader, strings.Trim(b.API.Proxy.ListenPath, "/"), requestDef.RelativeURL}, "/")

			thisRequest, createReqErr := http.NewRequest(requestDef.Method, absURL, bytes.NewBuffer([]byte(requestDef.Body)))
			if createReqErr != nil {
				log.Error("Failure generating batch request for request spec index: ", i)
				ReturnError(fmt.Sprintf("Batch request creation failed on request index %i", i), w)
				return
				return
			}

			// Add headers
			for k, v := range(requestDef.Headers) {
				thisRequest.Header.Add(k, v)
			}

			requestSet = append(requestSet, thisRequest)
		}

		// Run requests and collate responses
		ReplySet := []BatchReplyUnit{}

		if len(batchRequest.Requests) != len(requestSet) {
			log.Error("Something went wrong creating requests, they are of mismatched lengths!", len(batchRequest.Requests), len(requestSet))
		}

		if !batchRequest.SuppressParallelExecution {
			replies := make(chan BatchReplyUnit)
			for index, req := range(requestSet) {
				go b.doAsyncRequest(req, batchRequest.Requests[index].RelativeURL, replies)
			}

			for i := 0; i < len(batchRequest.Requests); i++ {
				val := BatchReplyUnit{}
				val = <- replies

				ReplySet = append(ReplySet, val)
			}
		} else {
			for index, req := range(requestSet) {
				reply := b.doSyncRequest(req, batchRequest.Requests[index].RelativeURL)
				ReplySet = append(ReplySet, reply)
			}
		}

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

// ReturnError returns an error to the http response writer
func ReturnError(err string, w http.ResponseWriter) {
	replyMessage := createError(err)
	DoJSONWrite(w, 400, replyMessage)
}

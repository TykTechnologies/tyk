package main

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
)

func CopyHttpRequest(r *http.Request) *http.Request {
	reqCopy := new(http.Request)
	*reqCopy = *r

	defer r.Body.Close()

	// Buffer body data
	var bodyBuffer bytes.Buffer
	bodyBuffer2 := new(bytes.Buffer)

	io.Copy(&bodyBuffer, r.Body)
	*bodyBuffer2 = bodyBuffer

	// Create new ReadClosers so we can split output
	r.Body = ioutil.NopCloser(&bodyBuffer)
	reqCopy.Body = ioutil.NopCloser(bodyBuffer2)

	return reqCopy
}

func CopyHttpResponse(r *http.Response) *http.Response {
	resCopy := new(http.Response)
	*resCopy = *r

	defer r.Body.Close()

	// Buffer body data
	var bodyBuffer bytes.Buffer
	bodyBuffer2 := new(bytes.Buffer)

	io.Copy(&bodyBuffer, r.Body)
	*bodyBuffer2 = bodyBuffer

	// Create new ReadClosers so we can split output
	r.Body = ioutil.NopCloser(&bodyBuffer)
	resCopy.Body = ioutil.NopCloser(bodyBuffer2)

	return resCopy
}

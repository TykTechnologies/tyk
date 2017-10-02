package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/mitchellh/mapstructure"
	"io/ioutil"
	"net/http"
	"strconv"
)

type ResponseTransformJQMiddleware struct {
	Spec *APISpec
}

func (h *ResponseTransformJQMiddleware) Init(c interface{}, spec *APISpec) error {
	h.Spec = spec

	return nil
}

func (h *ResponseTransformJQMiddleware) HandleResponse(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *SessionState) error {
	_, versionPaths, _, _ := h.Spec.Version(req)
	found, meta := h.Spec.CheckSpecMatchesStatus(req, versionPaths, TransformedJQResponse)
	if !found {
		return nil
	}

	defer res.Body.Close()

	t := meta.(*TransformJQSpec)

	var bodyObj interface{}
	dec := json.NewDecoder(res.Body)
	if err := dec.Decode(&bodyObj); err != nil {
		return err
	}
	jqObj := map[string]interface{}{
		"body":       bodyObj,
		"reqContext": ctxGetData(req),
		"resHeaders": res.Header,
	}

	if err := t.JQFilter.Handle(jqObj); err != nil {
		return errors.New("Response returned by upstream server is not a valid JSON")
	}

	if !t.JQFilter.Next() {
		return errors.New("Error while applying JQ filter to upstream response")
	}

	transformed, _ := json.Marshal(t.JQFilter.Value())

	bodyBuffer := bytes.NewBuffer(transformed)
	res.Header.Set("Content-Length", strconv.Itoa(bodyBuffer.Len()))
	res.ContentLength = int64(bodyBuffer.Len())
	res.Body = ioutil.NopCloser(bodyBuffer)

	// Second optional element is an object like:
	// { "output_headers": {"header_name": "header_value", ...}}
	if !t.JQFilter.Next() {
		return nil
	}

	options := t.JQFilter.Value()

	var opts JQTransformOptions
	err := mapstructure.Decode(options, &opts)
	if err != nil {
		return errors.New("Errors while reading JQ filter transform options")
	}

	// Replace header in the response
	for hName, hValue := range opts.OutputHeaders {
		res.Header.Set(hName, hValue)
	}

	return nil
}

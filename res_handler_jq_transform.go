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

type ResponseTransformJQOptions struct {
	//FlushInterval time.Duration
}

type ResponseTransformJQMiddleware struct {
	Spec   *APISpec
	config ResponseTransformJQOptions
}

func (h *ResponseTransformJQMiddleware) Init(c interface{}, spec *APISpec) error {
	h.Spec = spec
	if err := mapstructure.Decode(c, &h.config); err != nil {
		log.Error(err)
		return err
	}
	return nil
}

func (h *ResponseTransformJQMiddleware) HandleResponse(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *SessionState) error {
	_, versionPaths, _, _ := h.Spec.GetVersionData(req)
	found, meta := h.Spec.CheckSpecMatchesStatus(req, versionPaths, TransformedJQResponse)
	if !found {
		return nil
	}

	// Read the body:
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	t := meta.(*TransformJQSpec)

	reqContextJson, _ := json.Marshal(ctxGetData(req))

	resHeadersJson, _ := json.Marshal(res.Header)

	bodyBuffer := bytes.NewBufferString("[")
	bodyBuffer.Write(reqContextJson)
	bodyBuffer.WriteString(",")
	bodyBuffer.Write(resHeadersJson)
	bodyBuffer.WriteString(",")
	bodyBuffer.Write(body)
	bodyBuffer.WriteString("]")

	err = t.JQFilter.HandleJson(string(bodyBuffer.String()))
	if err != nil {
		return errors.New("Response returned by upstream server is not a valid JSON")
	}

	if t.JQFilter.Next() {
		transformed, _ := json.Marshal(t.JQFilter.Value())

		bodyBuffer := bytes.NewBuffer(transformed)
		res.Header.Set("Content-Length", strconv.Itoa(bodyBuffer.Len()))
		res.ContentLength = int64(bodyBuffer.Len())
		res.Body = ioutil.NopCloser(bodyBuffer)
	} else {
		errors.New("Error while applying JQ filter to upstream response")
	}

	// Second optional element is an object like:
	// { "output_headers": {"header_name": "header_value", ...}}
	if t.JQFilter.Next() {
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
	}

	return nil
}

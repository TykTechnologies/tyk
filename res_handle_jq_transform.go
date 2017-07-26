package main

import (
	"bytes"
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

	t.JQFilter.HandleJson(string(body))
	t.JQFilter.Next()
	transformed := t.JQFilter.ValueJson()

	//transformed := "{\"name\": \"hello\"}"
	bodyBuffer := bytes.NewBufferString(transformed)
	res.Header.Set("Content-Length", strconv.Itoa(bodyBuffer.Len()))
	res.ContentLength = int64(bodyBuffer.Len())
	res.Body = ioutil.NopCloser(bodyBuffer)

	return nil
}

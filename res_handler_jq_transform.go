package main

import (
	"bytes"
	"encoding/json"
	"github.com/TykTechnologies/tyk/user"
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

func (h *ResponseTransformJQMiddleware) HandleResponse(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) error {
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

	jq_result, err := lockedJQTransform(t, jqObj)
	if err != nil {
		return err
	}

	transformed, _ := json.Marshal(jq_result.Body)

	bodyBuffer := bytes.NewBuffer(transformed)
	res.Header.Set("Content-Length", strconv.Itoa(bodyBuffer.Len()))
	res.ContentLength = int64(bodyBuffer.Len())
	res.Body = ioutil.NopCloser(bodyBuffer)

	// Replace header in the response
	for hName, hValue := range jq_result.OutputHeaders {
		res.Header.Set(hName, hValue)
	}

	return nil
}

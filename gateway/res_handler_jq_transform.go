//go:build jq
// +build jq

package gateway

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/TykTechnologies/tyk/user"
)

type ResponseTransformJQMiddleware struct {
	Spec *APISpec
	Gw   *Gateway `json:"-"`
}

func (h *ResponseTransformJQMiddleware) Init(c interface{}, spec *APISpec) error {
	h.Spec = spec

	return nil
}

func (h *ResponseTransformJQMiddleware) HandleError(rw http.ResponseWriter, req *http.Request) {
}

func (h *ResponseTransformJQMiddleware) HandleResponse(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) error {
	versionInfo, _ := h.Spec.Version(req)
	versionPaths, _ := a.RxPaths[versionInfo.Name]
	found, meta := h.Spec.CheckSpecMatchesStatus(req, versionPaths, TransformedJQResponse)
	if !found {
		return nil
	}

	defer res.Body.Close()

	ts := meta.(*TransformJQSpec)

	var bodyObj interface{}
	dec := json.NewDecoder(res.Body)
	if err := dec.Decode(&bodyObj); err != nil {
		return err
	}
	jqObj := map[string]interface{}{
		"body":                  bodyObj,
		"_tyk_context":          ctxGetData(req),
		"_tyk_response_headers": res.Header,
	}

	jqResult, err := lockedJQTransform(h.Spec, ts, jqObj)
	if err != nil {
		return err
	}

	transformed, _ := json.Marshal(jqResult.Body)

	bodyBuffer := bytes.NewBuffer(transformed)
	res.Header.Set("Content-Length", strconv.Itoa(bodyBuffer.Len()))
	res.ContentLength = int64(bodyBuffer.Len())
	res.Body = ioutil.NopCloser(bodyBuffer)

	// Replace header in the response
	ignoreCanonical := h.GetConfig().IgnoreCanonicalMIMEHeaderKey
	for hName, hValue := range jqResult.RewriteHeaders {
		setCustomHeader(res.Header, hName, hValue, ignoreCanonical)
	}

	return nil
}

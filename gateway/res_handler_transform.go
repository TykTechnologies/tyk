package gateway

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/clbanning/mxj"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/user"
)

const (
	msgBodyTransformed = "Body transformed"
)

type ResponseTransformMiddleware struct {
	BaseTykResponseHandler
}

func (r *ResponseTransformMiddleware) Base() *BaseTykResponseHandler {
	return &r.BaseTykResponseHandler
}

func (r *ResponseTransformMiddleware) Enabled() bool {
	for _, version := range r.Spec.VersionData.Versions {
		if len(version.ExtendedPaths.TransformResponse) > 0 {
			for _, transformResponse := range version.ExtendedPaths.TransformResponse {
				if !transformResponse.Disabled {
					return true
				}
			}
		}
	}
	return false
}

func (r *ResponseTransformMiddleware) Name() string {
	return "ResponseTransformMiddleware"
}

func (r *ResponseTransformMiddleware) Init(c interface{}, spec *APISpec) error {
	r.Spec = spec
	return nil
}

func respBodyReader(req *http.Request, resp *http.Response) io.ReadCloser {

	if req.Header.Get(header.AcceptEncoding) == "" {
		return resp.Body
	}

	switch resp.Header.Get(header.ContentEncoding) {
	case "gzip":
		reader, err := gzip.NewReader(resp.Body)
		if err != nil {
			log.Error("Body decompression error:", err)
			return ioutil.NopCloser(bytes.NewReader(nil))
		}

		// represents unknown length
		resp.ContentLength = 0

		return reader
	case "deflate":
		// represents unknown length
		resp.ContentLength = 0

		return flate.NewReader(resp.Body)
	}

	return resp.Body
}

func compressBuffer(in bytes.Buffer, encoding string) (out bytes.Buffer) {
	switch encoding {
	case "gzip":
		zw := gzip.NewWriter(&out)
		zw.Write(in.Bytes())
		zw.Close()
	case "deflate":
		zw, _ := flate.NewWriter(&out, 1)
		zw.Write(in.Bytes())
		zw.Close()
	default:
		out = in
	}

	return out
}

func (r *ResponseTransformMiddleware) HandleError(rw http.ResponseWriter, req *http.Request) {
}

func (r *ResponseTransformMiddleware) HandleResponse(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) error {
	logger := r.logger().WithFields(logrus.Fields{
		"prefix":      "outbound-transform",
		"server_name": r.Spec.Proxy.TargetURL,
		"api_id":      r.Spec.APIID,
		"path":        req.URL.Path,
	})

	versionInfo, _ := r.Spec.Version(req)
	versionPaths := r.Spec.RxPaths[versionInfo.Name]
	found, meta := r.Spec.CheckSpecMatchesStatus(req, versionPaths, TransformedResponse)

	if !found {
		logger.Warning("CheckSpecMatchesStatus not found. Transformation stopped.")
		return nil
	}
	tmeta := meta.(*TransformSpec)

	respBody := respBodyReader(req, res)
	body, _ := ioutil.ReadAll(respBody)
	defer respBody.Close()

	// Put into an interface:
	bodyData := make(map[string]interface{})
	switch tmeta.TemplateData.Input {
	case apidef.RequestXML:
		if len(body) == 0 {
			body = []byte("<_/>")
		}

		mxj.XmlCharsetReader = WrappedCharsetReader
		var err error

		xmlMap, err := mxj.NewMapXml(body) // unmarshal
		if err != nil {
			logger.WithError(err).Error("Error unmarshalling XML")
			//todo return error
			break
		}
		for k, v := range xmlMap {
			bodyData[k] = v
		}
	default: // apidef.RequestJSON
		if len(body) == 0 {
			body = []byte("{}")
		}

		var tempBody interface{}
		if err := json.Unmarshal(body, &tempBody); err != nil {
			logger.WithError(err).Error("Error unmarshalling JSON")
			//todo return error
			break
		}

		switch tempBody.(type) {
		case []interface{}:
			bodyData["array"] = tempBody
		case map[string]interface{}:
			bodyData = tempBody.(map[string]interface{})
		}
	}

	if r.Spec.EnableContextVars {
		bodyData["_tyk_context"] = ctxGetData(req)
	}

	if tmeta.TemplateData.EnableSession {
		if session := ctxGetSession(req); session != nil {
			bodyData["_tyk_meta"] = session.MetaData
		} else {
			logger.Error("Session context was enabled but not found.")
		}
	}

	// Apply to template
	var bodyBuffer bytes.Buffer
	if err := tmeta.Template.Execute(&bodyBuffer, bodyData); err != nil {
		logger.WithError(err).Error("Failed to apply template to request")
	} else {
		logger.Debugf("%s", msgBodyTransformed)
	}

	// Re-compress if original upstream response was compressed
	encoding := res.Header.Get("Content-Encoding")
	bodyBuffer = compressBuffer(bodyBuffer, encoding)

	res.ContentLength = int64(bodyBuffer.Len())
	res.Header.Set("Content-Length", strconv.Itoa(bodyBuffer.Len()))
	res.Body = ioutil.NopCloser(&bodyBuffer)

	return nil
}

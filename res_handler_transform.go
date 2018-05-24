package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/Sirupsen/logrus"
	"github.com/clbanning/mxj"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"
)

type ResponseTransformMiddleware struct {
	Spec *APISpec
}

func (h *ResponseTransformMiddleware) Init(c interface{}, spec *APISpec) error {
	h.Spec = spec
	return nil
}

func respBodyReader(req *http.Request, resp *http.Response) io.ReadCloser {
	if req.Header.Get("Accept-Encoding") == "" {
		return resp.Body
	}

	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err := gzip.NewReader(resp.Body)
		if err != nil {
			log.Error("Body decompression error:", err)
			return ioutil.NopCloser(bytes.NewReader(nil))
		}
		return reader
	case "deflate":
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

func (h *ResponseTransformMiddleware) HandleResponse(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) error {
	_, versionPaths, _, _ := h.Spec.Version(req)
	found, meta := h.Spec.CheckSpecMatchesStatus(req, versionPaths, TransformedResponse)

	if !found {
		return nil
	}
	tmeta := meta.(*TransformSpec)

	respBody := respBodyReader(req, res)
	defer respBody.Close()

	// Put into an interface:
	var bodyData map[string]interface{}
	switch tmeta.TemplateData.Input {
	case apidef.RequestXML:
		mxj.XmlCharsetReader = WrappedCharsetReader
		var err error

		bodyData, err = mxj.NewMapXmlReader(respBody) // unmarshal
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix":      "outbound-transform",
				"server_name": h.Spec.Proxy.TargetURL,
				"api_id":      h.Spec.APIID,
				"path":        req.URL.Path,
			}).Error("Error unmarshalling XML: ", err)
		}
	default: // apidef.RequestJSON
		if err := json.NewDecoder(respBody).Decode(&bodyData); err != nil {
			log.WithFields(logrus.Fields{
				"prefix":      "outbound-transform",
				"server_name": h.Spec.Proxy.TargetURL,
				"api_id":      h.Spec.APIID,
				"path":        req.URL.Path,
			}).Error("Error unmarshalling JSON: ", err)
		}
	}

	// Apply to template
	var bodyBuffer bytes.Buffer
	if err := tmeta.Template.Execute(&bodyBuffer, bodyData); err != nil {
		log.WithFields(logrus.Fields{
			"prefix":      "outbound-transform",
			"server_name": h.Spec.Proxy.TargetURL,
			"api_id":      h.Spec.APIID,
			"path":        req.URL.Path,
		}).Error("Failed to apply template to request: ", err)
	}

	// Re-compress if original upstream response was compressed
	encoding := res.Header.Get("Content-Encoding")
	bodyBuffer = compressBuffer(bodyBuffer, encoding)

	res.ContentLength = int64(bodyBuffer.Len())
	res.Header.Set("Content-Length", strconv.Itoa(bodyBuffer.Len()))
	res.Body = ioutil.NopCloser(&bodyBuffer)

	return nil
}

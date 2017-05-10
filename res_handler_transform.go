package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/Sirupsen/logrus"
	"github.com/clbanning/mxj"
	"github.com/mitchellh/mapstructure"

	"github.com/TykTechnologies/tyk/apidef"
)

type ResponsetransformOptions struct {
	//FlushInterval time.Duration
}

type ResponseTransformMiddleware struct {
	Spec   *APISpec
	config ResponsetransformOptions
}

func (rt ResponseTransformMiddleware) New(c interface{}, spec *APISpec) (TykResponseHandler, error) {
	handler := ResponseTransformMiddleware{}
	moduleConfig := ResponsetransformOptions{}

	if err := mapstructure.Decode(c, &moduleConfig); err != nil {
		log.Error(err)
		return nil, err
	}

	handler.config = moduleConfig
	handler.Spec = spec

	log.Debug("Response body transform processor initialised")

	return handler, nil
}

func (rt ResponseTransformMiddleware) HandleResponse(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *SessionState) error {
	_, versionPaths, _, _ := rt.Spec.GetVersionData(req)
	found, meta := rt.Spec.CheckSpecMatchesStatus(req.URL.Path, req.Method, versionPaths, TransformedResponse)
	if !found {
		return nil
	}
	tmeta := meta.(*TransformSpec)

	// Read the body:
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	// Put into an interface:
	var bodyData interface{}
	switch tmeta.TemplateData.Input {
	case apidef.RequestXML:
		mxj.XmlCharsetReader = WrappedCharsetReader
		bodyData, err = mxj.NewMapXml(body) // unmarshal
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix":      "outbound-transform",
				"server_name": rt.Spec.APIDefinition.Proxy.TargetURL,
				"api_id":      rt.Spec.APIDefinition.APIID,
				"path":        req.URL.Path,
			}).Error("Error unmarshalling XML: ", err)
		}
	case apidef.RequestJSON:
		json.Unmarshal(body, &bodyData)
	default:
		json.Unmarshal(body, &bodyData)
	}

	// Apply to template
	var bodyBuffer bytes.Buffer
	if err = tmeta.Template.Execute(&bodyBuffer, bodyData); err != nil {
		log.WithFields(logrus.Fields{
			"prefix":      "outbound-transform",
			"server_name": rt.Spec.APIDefinition.Proxy.TargetURL,
			"api_id":      rt.Spec.APIDefinition.APIID,
			"path":        req.URL.Path,
		}).Error("Failed to apply template to request: ", err)
	}

	res.ContentLength = int64(bodyBuffer.Len())
	res.Header.Set("Content-Length", strconv.Itoa(bodyBuffer.Len()))
	res.Body = ioutil.NopCloser(&bodyBuffer)

	return nil
}

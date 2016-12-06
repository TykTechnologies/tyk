package main

import (
	"bytes"
	"encoding/json"
	"github.com/TykTechnologies/logrus"
	"github.com/clbanning/mxj"
	"github.com/TykTechnologies/tykcommon"
	"github.com/mitchellh/mapstructure"
	"io/ioutil"
	"net/http"
	"strconv"
)

type ResponsetransformOptions struct {
	//FlushInterval time.Duration
}

type ResponseTransformMiddleware struct {
	Spec   *APISpec
	config ResponsetransformOptions
}

func (rt ResponseTransformMiddleware) New(c interface{}, spec *APISpec) (TykResponseHandler, error) {
	thisHandler := ResponseTransformMiddleware{}
	thisModuleConfig := ResponsetransformOptions{}

	err := mapstructure.Decode(c, &thisModuleConfig)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	thisHandler.config = thisModuleConfig
	thisHandler.Spec = spec

	log.Debug("Response body transform processor initialised")

	return thisHandler, nil
}

func (rt ResponseTransformMiddleware) HandleResponse(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *SessionState) error {
	// New request checker, more targetted, less likely to fail
	var stat RequestStatus
	var meta interface{}
	var found bool

	_, versionPaths, _, _ := rt.Spec.GetVersionData(req)
	found, meta = rt.Spec.CheckSpecMatchesStatus(req.URL.Path, req.Method, versionPaths, TransformedResponse)
	if found {
		stat = StatusTransformResponse
	}

	if stat == StatusTransformResponse {
		thisMeta := meta.(*TransformSpec)

		// Read the body:
		defer res.Body.Close()
		body, err := ioutil.ReadAll(res.Body)

		// Put into an interface:
		var bodyData interface{}
		switch thisMeta.TemplateMeta.TemplateData.Input {
		case tykcommon.RequestXML:
			mxj.XmlCharsetReader = WrappedCharsetReader
			var xErr error
			bodyData, xErr = mxj.NewMapXml(body) // unmarshal
			if xErr != nil {
				log.WithFields(logrus.Fields{
					"prefix":      "outbound-transform",
					"server_name": rt.Spec.APIDefinition.Proxy.TargetURL,
					"api_id":      rt.Spec.APIDefinition.APIID,
					"path":        req.URL.Path,
				}).Error("Error unmarshalling XML: ", err)
			}
		case tykcommon.RequestJSON:
			json.Unmarshal(body, &bodyData)
		default:
			json.Unmarshal(body, &bodyData)
		}

		// Apply to template
		var bodyBuffer bytes.Buffer
		err = thisMeta.Template.Execute(&bodyBuffer, bodyData)

		if err != nil {
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
	}

	return nil
}

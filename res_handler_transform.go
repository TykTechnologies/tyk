package main

import (
	"bytes"
	"encoding/json"
	"github.com/lonelycode/tykcommon"
	"github.com/mitchellh/mapstructure"
	//"io"
	"io/ioutil"
	"net/http"
	//"time"
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

	log.Warning("Response body transform processor initialised")

	return thisHandler, nil
}

// func (rt ResponseTransformMiddleware) copyResponse(dst io.Writer, src io.Reader) {
// 	if rt.FlushInterval != 0 {
// 		if wf, ok := dst.(writeFlusher); ok {
// 			mlw := &maxLatencyWriter{
// 				dst:     wf,
// 				latency: p.FlushInterval,
// 				done:    make(chan bool),
// 			}
// 			go mlw.flushLoop()
// 			defer mlw.stop()
// 			dst = mlw
// 		}
// 	}

// 	io.Copy(dst, src)
// }

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
		thisMeta := meta.(TransformSpec)

		// Read the body:
		defer res.Body.Close()
		body, err := ioutil.ReadAll(res.Body)

		// Put into an interface:
		var bodyData interface{}
		switch thisMeta.TemplateMeta.TemplateData.Input {
		case tykcommon.RequestXML:
			log.Warning("XML Input is not supprted")
		case tykcommon.RequestJSON:
			json.Unmarshal(body, &bodyData)
		default:
			json.Unmarshal(body, &bodyData)
		}

		// Apply to template
		var bodyBuffer bytes.Buffer
		log.Warning("RUNNING TRANSFORM")
		err = thisMeta.Template.Execute(&bodyBuffer, bodyData)

		if err != nil {
			log.Error("Failed to apply template to request: ", err)
		}

		res.ContentLength = int64(bodyBuffer.Len())
		res.Header.Set("Content-Length", strconv.Itoa(bodyBuffer.Len()))
		res.Body = ioutil.NopCloser(&bodyBuffer)
	}

	return nil
}

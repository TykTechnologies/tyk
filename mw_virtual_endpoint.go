package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	_ "github.com/robertkrimen/otto/underscore"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/user"

	"github.com/Sirupsen/logrus"
)

// RequestObject is marshalled to JSON string and passed into JSON middleware
type RequestObject struct {
	Headers map[string][]string
	Body    string
	URL     string
	Params  map[string][]string
	Scheme  string
}

type ResponseObject struct {
	Body    string
	Headers map[string]string
	Code    int
}

type VMResponseObject struct {
	Response    ResponseObject
	SessionMeta map[string]string
}

// DynamicMiddleware is a generic middleware that will execute JS code before continuing
type VirtualEndpoint struct {
	BaseMiddleware
	sh SuccessHandler
}

func (d *VirtualEndpoint) Name() string {
	return "VirtualEndpoint"
}

func preLoadVirtualMetaCode(meta *apidef.VirtualMeta, j TykJSVM) {
	// the only call site uses (&foo, &bar) so meta and j won't be
	// nil.
	var src string
	log := j.GetLog()
	//to make this not panic for both jsvms always make sure it is read into a string
	switch meta.FunctionSourceType {
	case "file":
		log.Debug("Loading JS Endpoint File: ", meta.FunctionSourceURI)
		f, err := ioutil.ReadFile(meta.FunctionSourceURI)
		if err != nil {
			log.WithError(err).Error("Failed to open Endpoint JS")
			return
		}
		src = string(f)
	case "blob":
		if config.Global().DisableVirtualPathBlobs {
			log.Error("[JSVM] Blobs not allowed on this node")
			return
		}
		log.Debug("Loading JS blob")
		js, err := base64.StdEncoding.DecodeString(meta.FunctionSourceURI)
		if err != nil {
			log.WithError(err).Error("Failed to load blob JS")
			return
		}
		src = string(js)
	default:
		log.Error("Type must be either file or blob (base64)!")
		return
	}
	if _, err := j.Run(src); err != nil {
		log.WithError(err).Error("Could not load virtual endpoint JS")
	}
}

func (d *VirtualEndpoint) Init() {
	d.sh = SuccessHandler{d.BaseMiddleware}
}

func (d *VirtualEndpoint) EnabledForSpec() bool {
	if !d.Spec.GlobalConfig.EnableJSVM {
		return false
	}
	for _, version := range d.Spec.VersionData.Versions {
		if len(version.ExtendedPaths.Virtual) > 0 {
			return true
		}
	}
	return false
}

func (d *VirtualEndpoint) getMetaFromRequest(r *http.Request) *apidef.VirtualMeta {
	_, versionPaths, _, _ := d.Spec.Version(r)
	found, meta := d.Spec.CheckSpecMatchesStatus(r, versionPaths, VirtualPath)
	if !found {
		return nil
	}

	vmeta, ok := meta.(*apidef.VirtualMeta)
	if !ok {
		return nil
	}

	return vmeta
}

func (d *VirtualEndpoint) ServeHTTPForCache(w http.ResponseWriter, r *http.Request, vmeta *apidef.VirtualMeta) *http.Response {
	t1 := time.Now().UnixNano()

	if vmeta == nil {
		if vmeta = d.getMetaFromRequest(r); vmeta == nil {
			return nil
		}
	}

	// Create the proxy object
	originalBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		d.Logger().WithError(err).Error("Failed to read request body!")
		return nil
	}
	defer r.Body.Close()

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	requestData := RequestObject{
		Headers: r.Header,
		Body:    string(originalBody),
		URL:     r.URL.String(),
		Scheme:  scheme,
	}

	// We need to copy the body _back_ for the decode
	r.Body = ioutil.NopCloser(bytes.NewReader(originalBody))
	parseForm(r)
	requestData.Params = r.Form

	requestAsJson, err := json.Marshal(requestData)
	if err != nil {
		d.Logger().WithError(err).Error("Failed to encode request object for virtual endpoint")
		return nil
	}

	// Encode the configuration data too
	specAsJson := specToJson(d.Spec)

	session := new(user.SessionState)

	// Encode the session object (if not a pre-process)
	if vmeta.UseSession {
		session = ctxGetSession(r)
	}

	sessionAsJson, err := json.Marshal(session)
	if err != nil {
		d.Logger().WithError(err).Error("Failed to encode session for VM")
		return nil
	}
	// Run the middleware
	err, code, returnDataStr := d.Spec.JSVM.RunJSRequestVirtual(d, d.logger, vmeta, string(requestAsJson), string(sessionAsJson), specAsJson)
	if err != nil {
		log.Errorf("JSVM VE error: %v", err)
		return nil
	}
	if code != -1 {
		return nil
	}
	// Decode the return object
	newResponseData := VMResponseObject{}
	if err := json.Unmarshal([]byte(returnDataStr), &newResponseData); err != nil {
		d.Logger().WithError(err).Error("Failed to decode virtual endpoint response data on return from VM: ",
			"; Returned: ", returnDataStr)
		return nil
	}

	// Save the sesison data (if modified)
	if vmeta.UseSession {
		newMeta := mapStrsToIfaces(newResponseData.SessionMeta)
		if !reflect.DeepEqual(session.MetaData, newMeta) {
			session.MetaData = newMeta
			ctxSetSession(r, session, "", true)
		}
	}

	d.Logger().Debug("JSVM Virtual Endpoint execution took: (ns) ", time.Now().UnixNano()-t1)

	copiedResponse := forceResponse(w, r, &newResponseData, d.Spec, session, false, d.Logger())

	if copiedResponse != nil {
		go d.sh.RecordHit(r, 0, copiedResponse.StatusCode, copiedResponse)
	}

	return copiedResponse
}

func forceResponse(w http.ResponseWriter,
	r *http.Request,
	newResponseData *VMResponseObject,
	spec *APISpec,
	session *user.SessionState, isPre bool, logger *logrus.Entry) *http.Response {
	responseMessage := []byte(newResponseData.Response.Body)

	// Create an http.Response object so we can send it tot he cache middleware
	newResponse := new(http.Response)
	newResponse.Header = make(map[string][]string)

	requestTime := time.Now().UTC().Format(http.TimeFormat)

	for header, value := range newResponseData.Response.Headers {
		newResponse.Header.Set(header, value)
	}

	newResponse.ContentLength = int64(len(responseMessage))
	newResponse.Body = nopCloser{
		ReadSeeker: bytes.NewReader(responseMessage),
	}
	newResponse.StatusCode = newResponseData.Response.Code
	newResponse.Proto = "HTTP/1.0"
	newResponse.ProtoMajor = 1
	newResponse.ProtoMinor = 0
	newResponse.Header.Set("Server", "tyk")
	newResponse.Header.Set("Date", requestTime)

	// Check if it is a loop
	loc := newResponse.Header.Get("Location")
	if (newResponse.StatusCode == 301 || newResponse.StatusCode == 302) && strings.HasPrefix(loc, "tyk://") {
		loopURL, err := url.Parse(newResponse.Header.Get("Location"))
		if err != nil {
			logger.WithError(err).WithField("loop", loc).Error("Failed to parse loop url")
		} else {
			ctxSetOrigRequestURL(r, r.URL)
			r.URL = loopURL
		}

		return nil
	}

	if !isPre {
		// Handle response middleware
		if err := handleResponseChain(spec.ResponseChain, w, newResponse, r, session); err != nil {
			logger.WithError(err).Error("Response chain failed! ")
		}
	}

	handleForcedResponse(w, newResponse, session, spec)

	// Record analytics
	return newResponse
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (d *VirtualEndpoint) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	vmeta := d.getMetaFromRequest(r)
	if vmeta == nil {
		// nothing can be done here, reply with 200 to allow proxy to target
		return nil, http.StatusOK
	}

	if res := d.ServeHTTPForCache(w, r, vmeta); res == nil {
		if vmeta.ProxyOnError {
			return nil, http.StatusOK
		} else {
			return errors.New("Error during virtual endpoint execution. Contact Administrator for more details."), http.StatusInternalServerError
		}
	}

	return nil, mwStatusRespond
}

func (d *VirtualEndpoint) HandleResponse(rw http.ResponseWriter, res *http.Response, ses *user.SessionState) {
	// Externalising this from the MW so we can re-use it elsewhere
	handleForcedResponse(rw, res, ses, d.Spec)
}

func handleForcedResponse(rw http.ResponseWriter, res *http.Response, ses *user.SessionState, spec *APISpec) {
	defer res.Body.Close()

	// Close connections
	if spec.GlobalConfig.CloseConnections {
		res.Header.Set("Connection", "close")
	}

	// Add resource headers
	if ses != nil {
		// We have found a session, lets report back
		quotaMax, quotaRemaining, _, quotaRenews := ses.GetQuotaLimitByAPIID(spec.APIID)
		res.Header.Set(XRateLimitLimit, strconv.Itoa(int(quotaMax)))
		res.Header.Set(XRateLimitRemaining, strconv.Itoa(int(quotaRemaining)))
		res.Header.Set(XRateLimitReset, strconv.Itoa(int(quotaRenews)))
	}

	copyHeader(rw.Header(), res.Header)

	rw.WriteHeader(res.StatusCode)
	io.Copy(rw, res.Body)
}

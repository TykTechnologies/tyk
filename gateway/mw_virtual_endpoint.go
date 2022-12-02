package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/robertkrimen/otto"
	_ "github.com/robertkrimen/otto/underscore"

	"github.com/TykTechnologies/tyk-pump/analytics"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/user"

	"github.com/sirupsen/logrus"
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
	SessionMeta map[string]interface{}
}

// DynamicMiddleware is a generic middleware that will execute JS code before continuing
type VirtualEndpoint struct {
	BaseMiddleware
	sh SuccessHandler
}

func (d *VirtualEndpoint) Name() string {
	return "VirtualEndpoint"
}

func (gw *Gateway) preLoadVirtualMetaCode(meta *apidef.VirtualMeta, j *JSVM) {
	// the only call site uses (&foo, &bar) so meta and j won't be
	// nil.
	var src interface{}
	switch meta.FunctionSourceType {
	case "file":
		j.Log.Debug("Loading JS Endpoint File: ", meta.FunctionSourceURI)
		f, err := os.Open(meta.FunctionSourceURI)
		if err != nil {
			j.Log.WithError(err).Error("Failed to open Endpoint JS")
			return
		}
		src = f
	case "blob":
		if gw.GetConfig().DisableVirtualPathBlobs {
			j.Log.Error("[JSVM] Blobs not allowed on this node")
			return
		}

		j.Log.Debug("Loading JS blob")
		js, err := base64.StdEncoding.DecodeString(meta.FunctionSourceURI)
		if err != nil {
			j.Log.WithError(err).Error("Failed to load blob JS")
			return
		}
		src = js
	default:
		j.Log.Error("Type must be either file or blob (base64)!")
		return
	}
	if _, err := j.VM.Run(src); err != nil {
		j.Log.WithError(err).Error("Could not load virtual endpoint JS")
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
	version, _ := d.Spec.Version(r)
	versionPaths := d.Spec.RxPaths[version.Name]
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

func (d *VirtualEndpoint) ServeHTTPForCache(w http.ResponseWriter, r *http.Request, vmeta *apidef.VirtualMeta) (*http.Response, error) {
	t1 := time.Now()
	if vmeta == nil {
		if vmeta = d.getMetaFromRequest(r); vmeta == nil {
			return nil, errors.New("No request info")
		}
	}

	// Create the proxy object
	originalBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
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
		return nil, fmt.Errorf("failed to encode request object for virtual endpoint: %w", err)
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
		return nil, fmt.Errorf("failed to encode session for VM: %w", err)
	}

	// Run the middleware

	vm := d.Spec.JSVM.VM.Copy()
	vm.Interrupt = make(chan func(), 1)
	d.Logger().Debug("Running: ", vmeta.ResponseFunctionName)
	// buffered, leaving no chance of a goroutine leak since the
	// spawned goroutine will send 0 or 1 values.
	ret := make(chan otto.Value, 1)
	errRet := make(chan error, 1)
	go func() {
		defer func() {
			// the VM executes the panic func that gets it
			// to stop, so we must recover here to not crash
			// the whole Go program.
			recover()
		}()
		returnRaw, err := vm.Run(vmeta.ResponseFunctionName + `(` + string(requestAsJson) + `, ` + string(sessionAsJson) + `, ` + specAsJson + `);`)
		ret <- returnRaw
		errRet <- err
	}()
	var returnRaw otto.Value
	t := time.NewTimer(d.Spec.JSVM.Timeout)
	select {
	case returnRaw = <-ret:
		if err := <-errRet; err != nil {
			return nil, fmt.Errorf("Failed to run JS middleware: %w", err)
		}
		t.Stop()
	case <-t.C:
		t.Stop()
		d.Logger().Error("JS middleware timed out after ", d.Spec.JSVM.Timeout)
		vm.Interrupt <- func() {
			// only way to stop the VM is to send it a func
			// that panics.
			panic("stop")
		}
		return nil, fmt.Errorf("JS middleware timed out after %s", d.Spec.JSVM.Timeout)
	}
	returnDataStr, _ := returnRaw.ToString()

	// Decode the return object
	newResponseData := VMResponseObject{}
	if err := json.Unmarshal([]byte(returnDataStr), &newResponseData); err != nil {
		d.Logger().WithError(err).WithField("return_data", returnDataStr).Errorf("Failed to decode virtual endpoint response data on return from VM")
		return nil, fmt.Errorf("Failed to decode virtual endpoint response: %w", err)
	}

	// Save the sesison data (if modified)
	if vmeta.UseSession {
		newMeta := newResponseData.SessionMeta
		if !reflect.DeepEqual(session.MetaData, newMeta) {
			session.MetaData = newMeta
			ctxSetSession(r, session, true, d.Gw.GetConfig().HashKeys)
		}
	}

	copiedResponse := d.Gw.forceResponse(w, r, &newResponseData, d.Spec, session, false, d.Logger())
	ms := DurationToMillisecond(time.Since(t1))
	d.Logger().Debug("JSVM Virtual Endpoint execution took: (ms) ", ms)

	if copiedResponse != nil {
		d.sh.RecordHit(r, analytics.Latency{Total: int64(ms)}, copiedResponse.StatusCode, copiedResponse)
	}

	return copiedResponse, nil
}

func (gw *Gateway) forceResponse(
	w http.ResponseWriter,
	r *http.Request,
	newResponseData *VMResponseObject,
	spec *APISpec,
	session *user.SessionState,
	isPre bool,
	logger *logrus.Entry,
) *http.Response {
	responseMessage := []byte(newResponseData.Response.Body)

	// Create an http.Response object so we can send it tot he cache middleware
	newResponse := new(http.Response)
	newResponse.Header = make(map[string][]string)

	requestTime := time.Now().UTC().Format(http.TimeFormat)
	ignoreCanonical := gw.GetConfig().IgnoreCanonicalMIMEHeaderKey
	for header, value := range newResponseData.Response.Headers {
		setCustomHeader(newResponse.Header, header, value, ignoreCanonical)
	}

	newResponse.ContentLength = int64(len(responseMessage))
	newResponse.Body = nopCloser{
		ReadSeeker: bytes.NewReader(responseMessage),
	}
	newResponse.StatusCode = newResponseData.Response.Code
	newResponse.Proto = r.Proto
	newResponse.ProtoMajor = r.ProtoMajor
	newResponse.ProtoMinor = r.ProtoMinor
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
		if _, err := handleResponseChain(spec.ResponseChain, w, newResponse, r, session); err != nil {
			logger.WithError(err).Error("Response chain failed! ")
		}
	}

	gw.handleForcedResponse(w, newResponse, session, spec)

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

	if _, err := d.ServeHTTPForCache(w, r, vmeta); err != nil {
		message := "Error during virtual endpoint execution. Contact Administrator for more details."
		d.Logger().WithError(err).WithField("vmeta", vmeta).Error(message)

		if vmeta.ProxyOnError {
			return nil, http.StatusOK
		}

		return errors.New(message), http.StatusInternalServerError
	}

	return nil, mwStatusRespond
}

func (d *VirtualEndpoint) HandleResponse(rw http.ResponseWriter, res *http.Response, ses *user.SessionState) {
	// Externalising this from the MW so we can re-use it elsewhere
	d.Gw.handleForcedResponse(rw, res, ses, d.Spec)
}

func (gw *Gateway) handleForcedResponse(rw http.ResponseWriter, res *http.Response, ses *user.SessionState, spec *APISpec) {
	defer res.Body.Close()

	// Close connections
	if spec.GlobalConfig.CloseConnections {
		res.Header.Set("Connection", "close")
	}

	// Add resource headers
	if ses != nil {
		// We have found a session, lets report back
		quotaMax, quotaRemaining, _, quotaRenews := ses.GetQuotaLimitByAPIID(spec.APIID)
		res.Header.Set(header.XRateLimitLimit, strconv.Itoa(int(quotaMax)))
		res.Header.Set(header.XRateLimitRemaining, strconv.Itoa(int(quotaRemaining)))
		res.Header.Set(header.XRateLimitReset, strconv.Itoa(int(quotaRenews)))
	}

	copyHeader(rw.Header(), res.Header, gw.GetConfig().IgnoreCanonicalMIMEHeaderKey)

	rw.WriteHeader(res.StatusCode)
	io.Copy(rw, res.Body)
}

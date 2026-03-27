package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"
)

// MiniResponseObject is marshalled to JSON and passed into JS response middleware.
// Field names deliberately match the MiniRequestObject convention (PascalCase)
// so that JS code can use response.SetHeaders, response.DeleteHeaders, etc.
// Body is a string (not []byte) so it serialises as a plain JSON string rather
// than base64, which is simpler for JS plugins to work with.
type MiniResponseObject struct {
	StatusCode    int
	Body          string
	Headers       map[string][]string
	SetHeaders    map[string]string
	DeleteHeaders []string
}

// VMResponseReturnObject is the decoded result from JS response middleware.
type VMResponseReturnObject struct {
	Response    MiniResponseObject
	SessionMeta map[string]string
}

// JSResponseMiddleware is a TykResponseHandler that runs JS response hooks
// via either the otto or goja JSVM drivers.
type JSResponseMiddleware struct {
	BaseTykResponseHandler
	hookName string
	spec     *APISpec
}

func (h *JSResponseMiddleware) Init(mwDef interface{}, spec *APISpec) error {
	mwDefinition, ok := mwDef.(apidef.MiddlewareDefinition)
	if !ok {
		return errors.New("invalid middleware definition for JS response hook")
	}
	h.hookName = mwDefinition.Name
	h.spec = spec
	return nil
}

func (h *JSResponseMiddleware) Name() string {
	return "JSResponseMiddleware"
}

func (h JSResponseMiddleware) Base() *BaseTykResponseHandler {
	return &h.BaseTykResponseHandler
}

func (h *JSResponseMiddleware) HandleError(rw http.ResponseWriter, req *http.Request) {
	handler := ErrorHandler{&BaseMiddleware{
		Spec: h.spec,
		Gw:   h.Gw,
	}}
	handler.HandleError(rw, req, "Middleware error", http.StatusInternalServerError, true)
}

func (h *JSResponseMiddleware) HandleResponse(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) error {
	logger := h.logger().WithFields(logrus.Fields{
		"prefix": "jsvm-response",
	})
	logger.Debugf("Response hook '%s' is called", h.hookName)

	t1 := time.Now().UnixNano()

	// Read the upstream response body.
	originalBody, err := io.ReadAll(res.Body)
	if err != nil {
		logger.WithError(err).Error("Failed to read response body")
		return errors.New("middleware error")
	}
	res.Body.Close()

	// Build the response object for JS.
	responseData := MiniResponseObject{
		StatusCode:    res.StatusCode,
		Body:          string(originalBody),
		Headers:       res.Header,
		SetHeaders:    map[string]string{},
		DeleteHeaders: []string{},
	}
	responseAsJSON, err := json.Marshal(responseData)
	if err != nil {
		logger.WithError(err).Error("Failed to encode response object for JS middleware")
		return errors.New("middleware error")
	}

	// Build a minimal request object.
	reqHeaders := req.Header
	host := req.Host
	if host == "" && req.URL != nil {
		host = req.URL.Host
	}
	if host != "" {
		reqHeaders = make(http.Header)
		for k, v := range req.Header {
			reqHeaders[k] = v
		}
		reqHeaders.Set("Host", host)
	}
	scheme := "http"
	if req.TLS != nil {
		scheme = "https"
	}

	requestData := MiniRequestObject{
		Headers:        reqHeaders,
		SetHeaders:     map[string]string{},
		DeleteHeaders:  []string{},
		Body:           nil,
		URL:            req.URL.String(),
		Params:         req.URL.Query(),
		AddParams:      map[string]string{},
		ExtendedParams: map[string][]string{},
		DeleteParams:   []string{},
		Method:         req.Method,
		RequestURI:     req.RequestURI,
		Scheme:         scheme,
	}
	requestAsJSON, err := json.Marshal(requestData)
	if err != nil {
		logger.WithError(err).Error("Failed to encode request object for JS response middleware")
		return errors.New("middleware error")
	}

	// Build session and spec JSON.
	session := &user.SessionState{}
	if ses != nil {
		session = ses
	}
	sessionAsJSON, err := json.Marshal(session)
	if err != nil {
		logger.WithError(err).Error("Failed to encode session for JS response middleware")
		return errors.New("middleware error")
	}

	specAsJSON := specToJson(h.spec)

	// Build the JS expression. We call DoProcessResponse on the middleware class.
	expr := h.hookName + `.DoProcessResponse(` + string(responseAsJSON) + `, ` + string(requestAsJSON) + `, ` + string(sessionAsJSON) + `, ` + specAsJSON + `);`
	logger.Debug("Running JS response hook: ", h.hookName)

	runner := h.spec.GetJSRunner()
	if runner == nil {
		logger.Error("JSVM isn't initialized")
		return errors.New("middleware error")
	}
	returnDataStr, runErr := runner.Run(expr)
	if runErr != nil {
		logger.WithError(runErr).Error("Failed to run JS response middleware")
		return errors.New("middleware error")
	}

	// Decode the return object.
	newResponseData := VMResponseReturnObject{}
	if err := json.Unmarshal([]byte(returnDataStr), &newResponseData); err != nil {
		logger.WithError(err).Error("Failed to decode JS response middleware return data: ", returnDataStr)
		return errors.New("middleware error")
	}

	// Apply header deletions.
	ignoreCanonical := h.Gw.GetConfig().IgnoreCanonicalMIMEHeaderKey
	for _, dh := range newResponseData.Response.DeleteHeaders {
		res.Header.Del(dh)
		if ignoreCanonical {
			delete(res.Header, dh)
		}
	}

	// Apply header additions/modifications.
	for k, v := range newResponseData.Response.SetHeaders {
		setCustomHeader(res.Header, k, v, ignoreCanonical)
	}

	// Apply body changes.
	newBody := []byte(newResponseData.Response.Body)
	res.Body = io.NopCloser(bytes.NewBuffer(newBody))
	res.ContentLength = int64(len(newBody))
	res.Header.Set("Content-Length", fmt.Sprintf("%d", len(newBody)))

	// Apply status code changes (only if explicitly set).
	if newResponseData.Response.StatusCode != 0 {
		res.StatusCode = newResponseData.Response.StatusCode
	}

	logger.Debug("JSVM response middleware execution took: (ns) ", time.Now().UnixNano()-t1)

	return nil
}

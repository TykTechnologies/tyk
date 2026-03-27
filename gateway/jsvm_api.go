package gateway

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/TykTechnologies/tyk/user"

	"github.com/sirupsen/logrus"
)

// JSVMAPIHelper contains the shared business logic for JS API bindings.
// Both otto (JSVM.LoadTykJSApi) and goja (GojaJSVM.registerAPI) delegate
// to these methods; only the VM value-wrapping differs.
type JSVMAPIHelper struct {
	Spec   *APISpec
	Gw     *Gateway
	Log    *logrus.Entry
	RawLog *logrus.Logger
}

func (h *JSVMAPIHelper) LogMessage(msg string) {
	h.Log.WithFields(logrus.Fields{
		"type": "log-msg",
	}).Info(msg)
}

func (h *JSVMAPIHelper) RawLogMessage(msg string) {
	h.RawLog.Print(msg + "\n")
}

func (h *JSVMAPIHelper) B64Decode(in string) (string, error) {
	out, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		out, err = base64.RawStdEncoding.DecodeString(in)
		if err != nil {
			h.Log.WithError(err).Error("Failed to base64 decode")
			return "", err
		}
	}
	return string(out), nil
}

func (h *JSVMAPIHelper) B64Encode(in string) string {
	return base64.StdEncoding.EncodeToString([]byte(in))
}

func (h *JSVMAPIHelper) RawB64Decode(in string) (string, error) {
	out, err := base64.RawStdEncoding.DecodeString(in)
	if err != nil {
		h.Log.WithError(err).Error("Failed to base64 decode")
		return "", err
	}
	return string(out), nil
}

func (h *JSVMAPIHelper) RawB64Encode(in string) string {
	return base64.RawStdEncoding.EncodeToString([]byte(in))
}

func (h *JSVMAPIHelper) MakeHTTPRequest(jsonHRO string) (string, error) {
	if jsonHRO == "undefined" {
		return "", nil
	}
	hro := TykJSHttpRequest{}
	if err := json.Unmarshal([]byte(jsonHRO), &hro); err != nil {
		h.Log.WithError(err).Error("JSVM: Failed to deserialise HTTP Request object")
		return "", err
	}

	domain := hro.Domain
	data := url.Values{}
	for k, v := range hro.FormData {
		data.Set(k, v)
	}

	u, err := url.ParseRequestURI(domain + hro.Resource)
	if err != nil {
		h.Log.WithError(err).Error("JSVM: Failed to parse request URI")
		return "", err
	}
	urlStr := u.String()

	var d string
	if hro.Body != "" {
		d = hro.Body
	} else if len(hro.FormData) > 0 {
		d = data.Encode()
	}

	var r *http.Request
	if d != "" {
		r, err = http.NewRequest(hro.Method, urlStr, strings.NewReader(d))
	} else {
		r, err = http.NewRequest(hro.Method, urlStr, nil)
	}
	if err != nil {
		h.Log.WithError(err).Error("JSVM: Failed to create HTTP request")
		return "", err
	}

	ignoreCanonical := h.Gw.GetConfig().IgnoreCanonicalMIMEHeaderKey
	for k, v := range hro.Headers {
		setCustomHeader(r.Header, k, v, ignoreCanonical)
	}
	r.Close = true

	maxSSLVersion := h.Gw.GetConfig().ProxySSLMaxVersion
	if h.Spec.Proxy.Transport.SSLMaxVersion > 0 {
		maxSSLVersion = h.Spec.Proxy.Transport.SSLMaxVersion
	}

	tr := &http.Transport{TLSClientConfig: &tls.Config{
		MaxVersion: maxSSLVersion,
	}}

	if cert := h.Gw.getUpstreamCertificate(r.Host, h.Spec); cert != nil {
		tr.TLSClientConfig.Certificates = []tls.Certificate{*cert}
	}

	if h.Gw.GetConfig().ProxySSLInsecureSkipVerify {
		tr.TLSClientConfig.InsecureSkipVerify = true
	}

	if h.Spec.Proxy.Transport.SSLInsecureSkipVerify {
		tr.TLSClientConfig.InsecureSkipVerify = true
	}

	tr.DialTLS = h.Gw.customDialTLSCheck(h.Spec, tr.TLSClientConfig)
	tr.Proxy = proxyFromAPI(h.Spec)

	client := &http.Client{Transport: tr}
	resp, err := client.Do(r)
	if err != nil {
		h.Log.WithError(err).Error("Request failed")
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		h.Log.WithError(err).Error("JSVM: Failed to read response body")
		return "", err
	}
	bodyStr := string(body)
	tykResp := TykJSHttpResponse{
		Code:        resp.StatusCode,
		Body:        bodyStr,
		Headers:     resp.Header,
		CodeComp:    resp.StatusCode,
		BodyComp:    bodyStr,
		HeadersComp: resp.Header,
	}

	retAsStr, err := json.Marshal(tykResp)
	if err != nil {
		h.Log.WithError(err).Error("JSVM: Failed to encode response")
		return "", err
	}
	return string(retAsStr), nil
}

func (h *JSVMAPIHelper) GetKeyData(apiKey, apiID string) string {
	obj, _ := h.Gw.handleGetDetail(apiKey, apiID, "", false)
	bs, _ := json.Marshal(obj)
	return string(bs)
}

func (h *JSVMAPIHelper) SetKeyData(apiKey, encodedSession, suppressReset string) error {
	newSession := user.SessionState{}
	if err := json.Unmarshal([]byte(encodedSession), &newSession); err != nil {
		h.Log.WithError(err).Error("Failed to decode the sesison data")
		return err
	}
	h.Gw.doAddOrUpdate(apiKey, &newSession, suppressReset == "1", false)
	return nil
}

func (h *JSVMAPIHelper) BatchRequest(requestSet string) (string, error) {
	h.Log.Debug("Batch input is: ", requestSet)
	unsafeBatchHandler := BatchRequestHandler{Gw: h.Gw}
	bs, err := unsafeBatchHandler.ManualBatchRequest([]byte(requestSet))
	if err != nil {
		h.Log.WithError(err).Error("Batch request error")
		return "", err
	}
	return string(bs), nil
}

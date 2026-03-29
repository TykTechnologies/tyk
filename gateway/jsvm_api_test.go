package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

// ---------------------------------------------------------------------------
// JSVMAPIHelper — MakeHTTPRequest
// ---------------------------------------------------------------------------

func TestJSVMAPIHelper_MakeHTTPRequest_Undefined(t *testing.T) {
	h := &JSVMAPIHelper{}
	result, err := h.MakeHTTPRequest("undefined")
	assert.NoError(t, err)
	assert.Equal(t, "", result)
}

func TestJSVMAPIHelper_MakeHTTPRequest_InvalidJSON(t *testing.T) {
	h := &JSVMAPIHelper{Log: logrus.NewEntry(logrus.New())}
	_, err := h.MakeHTTPRequest("{not valid json}")
	assert.Error(t, err)
}

func TestJSVMAPIHelper_MakeHTTPRequest_InvalidURL(t *testing.T) {
	// Empty domain+resource produces an empty string passed to url.ParseRequestURI,
	// which rejects it as an invalid URI for request.
	h := &JSVMAPIHelper{Log: logrus.NewEntry(logrus.New())}
	_, err := h.MakeHTTPRequest(`{"Method":"GET"}`)
	assert.Error(t, err)
}

func TestJSVMAPIHelper_MakeHTTPRequest_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("response body"))
	}))
	defer server.Close()

	ts := StartTest(nil)
	defer ts.Close()

	h := &JSVMAPIHelper{
		Gw:     ts.Gw,
		Spec:   &APISpec{APIDefinition: &apidef.APIDefinition{}},
		Log:    logrus.NewEntry(log),
		RawLog: rawLog,
	}

	input := fmt.Sprintf(`{"Method":"GET","Domain":"%s","Resource":"/"}`, server.URL)
	result, err := h.MakeHTTPRequest(input)
	require.NoError(t, err)
	assert.Contains(t, result, "response body")
}

func TestJSVMAPIHelper_MakeHTTPRequest_WithBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("created"))
	}))
	defer server.Close()

	ts := StartTest(nil)
	defer ts.Close()

	h := &JSVMAPIHelper{
		Gw:     ts.Gw,
		Spec:   &APISpec{APIDefinition: &apidef.APIDefinition{}},
		Log:    logrus.NewEntry(log),
		RawLog: rawLog,
	}

	input := fmt.Sprintf(`{"Method":"POST","Domain":"%s","Resource":"/","Body":"test body"}`, server.URL)
	result, err := h.MakeHTTPRequest(input)
	require.NoError(t, err)

	var tykResp TykJSHttpResponse
	require.NoError(t, json.Unmarshal([]byte(result), &tykResp))
	assert.Equal(t, http.StatusCreated, tykResp.Code)
}

func TestJSVMAPIHelper_MakeHTTPRequest_WithFormData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("form ok"))
	}))
	defer server.Close()

	ts := StartTest(nil)
	defer ts.Close()

	h := &JSVMAPIHelper{
		Gw:     ts.Gw,
		Spec:   &APISpec{APIDefinition: &apidef.APIDefinition{}},
		Log:    logrus.NewEntry(log),
		RawLog: rawLog,
	}

	input := fmt.Sprintf(`{"Method":"POST","Domain":"%s","Resource":"/","FormData":{"key":"value"}}`, server.URL)
	result, err := h.MakeHTTPRequest(input)
	require.NoError(t, err)
	assert.Contains(t, result, "form ok")
}

// ---------------------------------------------------------------------------
// JSVMAPIHelper — Base64 helpers
// ---------------------------------------------------------------------------

func TestJSVMAPIHelper_B64Decode_BothInvalid(t *testing.T) {
	h := &JSVMAPIHelper{Log: logrus.NewEntry(logrus.New())}
	_, err := h.B64Decode("!!!!!invalid!!!!!")
	assert.Error(t, err)
}

func TestJSVMAPIHelper_RawB64Decode_Valid(t *testing.T) {
	h := &JSVMAPIHelper{Log: logrus.NewEntry(logrus.New())}
	out, err := h.RawB64Decode("dGVzdA") // "test" without padding
	assert.NoError(t, err)
	assert.Equal(t, "test", out)
}

func TestJSVMAPIHelper_RawB64Decode_Invalid(t *testing.T) {
	h := &JSVMAPIHelper{Log: logrus.NewEntry(logrus.New())}
	_, err := h.RawB64Decode("!!!!!invalid!!!!!")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// JSVMAPIHelper — LogMessage / RawLogMessage
// ---------------------------------------------------------------------------

func TestJSVMAPIHelper_LogMessage(t *testing.T) {
	h := &JSVMAPIHelper{Log: logrus.NewEntry(logrus.New())}
	assert.NotPanics(t, func() { h.LogMessage("test log message") })
}

func TestJSVMAPIHelper_RawLogMessage(t *testing.T) {
	h := &JSVMAPIHelper{RawLog: logrus.New()}
	assert.NotPanics(t, func() { h.RawLogMessage("test raw log message") })
}

// ---------------------------------------------------------------------------
// JSVMAPIHelper — SetKeyData / GetKeyData / BatchRequest
// ---------------------------------------------------------------------------

func TestJSVMAPIHelper_SetKeyData_InvalidJSON(t *testing.T) {
	h := &JSVMAPIHelper{Log: logrus.NewEntry(logrus.New())}
	err := h.SetKeyData("key", "not valid json", "0")
	assert.Error(t, err)
}

func TestJSVMAPIHelper_GetKeyData_NonExistentKey(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	h := &JSVMAPIHelper{
		Spec:   &APISpec{APIDefinition: &apidef.APIDefinition{}},
		Gw:     ts.Gw,
		Log:    logrus.NewEntry(log),
		RawLog: rawLog,
	}

	// Non-existent key: should return valid JSON (typically "null").
	result := h.GetKeyData("nonexistent-key-jsvm-test", "")
	assert.NotEmpty(t, result)
	var v interface{}
	assert.NoError(t, json.Unmarshal([]byte(result), &v))
}

func TestJSVMAPIHelper_BatchRequest_InvalidJSON(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	h := &JSVMAPIHelper{
		Gw:     ts.Gw,
		Log:    logrus.NewEntry(log),
		RawLog: rawLog,
	}

	_, err := h.BatchRequest("{invalid json}")
	assert.Error(t, err)
}

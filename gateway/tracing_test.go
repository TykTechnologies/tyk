package gateway_test

import (
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTraceHttpRequest_toRequest(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const body = `{"foo":"bar"}`
	header := http.Header{}
	header.Add("key", "value")
	tr := &TraceHttpRequest{Path: "", Method: http.MethodPost, Body: body, Headers: header}

	request, err := tr.ToRequest(ts.Gw.GetConfig().IgnoreCanonicalMIMEHeaderKey)
	bodyInBytes, _ := ioutil.ReadAll(request.Body)

	assert.NoError(t, err)
	assert.Equal(t, http.MethodPost, request.Method)
	assert.Equal(t, "", request.URL.Host)
	assert.Equal(t, "", request.URL.Path)
	assert.Equal(t, header, request.Header)
	assert.Equal(t, string(bodyInBytes), body)
}

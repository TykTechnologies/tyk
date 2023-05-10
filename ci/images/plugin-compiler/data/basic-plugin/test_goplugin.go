package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/buger/jsonparser"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/user"
)

// MyPluginPre checks if session is NOT present, adds custom header
// with initial URI path and will be used as "pre" custom MW
func MyPluginPre(rw http.ResponseWriter, r *http.Request) {
	session := ctx.GetSession(r)
	if session != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	rw.Header().Add(header.XInitialURI, r.URL.RequestURI())
}

// MyPluginAuthCheck does custom auth and will be used as
// "auth_check" custom MW
func MyPluginAuthCheck(rw http.ResponseWriter, r *http.Request) {
	// perform auth (only one token "abc" is allowed)
	token := r.Header.Get(header.Authorization)
	if token != "abc" {
		rw.Header().Add(header.XAuthResult, "failed")
		rw.WriteHeader(http.StatusForbidden)
		_, _ = rw.Write([]byte("auth failed"))
		return
	}

	// create session
	session := &user.SessionState{
		OrgID: "default",
		Alias: "abc-session",
		KeyID: token,
	}

	ctx.SetSession(r, session, true, true)
	rw.Header().Add(header.XAuthResult, "OK")
}

// MyPluginPostKeyAuth checks if session is present, adds custom header with session-alias
// and will be used as "post_key_auth" custom MW
func MyPluginPostKeyAuth(rw http.ResponseWriter, r *http.Request) {
	session := ctx.GetSession(r)
	if session == nil {
		rw.Header().Add(header.XSessionAlias, "not found")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	rw.Header().Add(header.XSessionAlias, session.Alias)
}

// MyPluginPost prepares and sends reply, will be used as "post" custom MW
func MyPluginPost(rw http.ResponseWriter, r *http.Request) {

	replyData := map[string]interface{}{
		"message": "post message",
	}

	jsonData, err := json.Marshal(replyData)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	apiDefinition := ctx.GetDefinition(r)
	if apiDefinition == nil {
		rw.Header().Add("X-Plugin-Data", "null")
	} else {
		pluginConfig, ok := apiDefinition.ConfigData["my-context-data"].(string)
		if !ok || pluginConfig == "" {
			rw.Header().Add("X-Plugin-Data", "null")
		} else {
			rw.Header().Add("X-Plugin-Data", pluginConfig)
		}

	}
	rw.Header().Set(header.ContentType, header.ApplicationJSON)
	rw.WriteHeader(http.StatusOK)
	rw.Write(jsonData)
}

// MyPluginResponse intercepts response from upstream which we can then manipulate
func MyPluginResponse(rw http.ResponseWriter, res *http.Response, req *http.Request) {

	res.Header.Add("X-Response-Added", "resp-added")

	var buf bytes.Buffer

	buf.Write([]byte(`{"message":"response injected message"}`))

	res.Body = ioutil.NopCloser(&buf)

	apiDefinition := ctx.GetDefinition(req)
	if apiDefinition == nil {
		res.Header.Add("X-Plugin-Data", "null")
		return
	}
	pluginConfig, ok := apiDefinition.ConfigData["my-context-data"].(string)
	if !ok || pluginConfig == "" {
		res.Header.Add("X-Plugin-Data", "null")
		return
	}
	res.Header.Add("X-Plugin-Data", pluginConfig)
}

func MyPluginPerPathFoo(rw http.ResponseWriter, r *http.Request) {

	rw.Header().Add("X-foo", "foo")

}

func MyPluginPerPathBar(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Add("X-bar", "bar")

}

func MyPluginPerPathResp(rw http.ResponseWriter, r *http.Request) {
	// prepare data to send
	replyData := map[string]string{
		"current_time": "now",
	}

	jsonData, err := json.Marshal(replyData)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	// send HTTP response from Golang plugin
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	rw.Write(jsonData)
}

func MyAnalyticsPluginDeleteHeader(record *analytics.AnalyticsRecord) {
	str, err := base64.StdEncoding.DecodeString(record.RawResponse)
	if err != nil {
		return
	}

	var b = &bytes.Buffer{}
	b.Write(str)

	r := bufio.NewReader(b)
	var resp *http.Response
	resp, err = http.ReadResponse(r, nil)
	if err != nil {
		return
	}
	resp.Header.Del("Server")
	var bNew bytes.Buffer
	_ = resp.Write(&bNew)
	record.RawResponse = base64.StdEncoding.EncodeToString(bNew.Bytes())
}

func MyAnalyticsPluginMaskJSONLoginBody(record *analytics.AnalyticsRecord) {
	if record.ContentLength < 1 {
		return
	}
	d, err := base64.StdEncoding.DecodeString(record.RawRequest)
	if err != nil {
		return
	}
	var mask = []byte("\"****\"")
	const endOfHeaders = "\r\n\r\n"
	paths := [][]string{
		{"email"},
		{"password"},
		{"data", "email"},
		{"data", "password"},
	}
	if i := bytes.Index(d, []byte(endOfHeaders)); i > 0 || (i+4) < len(d) {
		body := d[i+4:]
		jsonparser.EachKey(body, func(idx int, _ []byte, _ jsonparser.ValueType, _ error) {
			body, _ = jsonparser.Set(body, mask, paths[idx]...)
		}, paths...)
		if err == nil {
			record.RawRequest = base64.StdEncoding.EncodeToString(append(d[:i+4], body...))
		}
	}
}

package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/headers"
	"github.com/TykTechnologies/tyk/user"
)

// MyPluginPre checks if session is NOT present, adds custom header
// with initial URI path and will be used as "pre" custom MW
func MyPluginPre(rw http.ResponseWriter, r *http.Request) {
	fmt.Println("PREAUTH")
	session := ctx.GetSession(r)
	if session != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	rw.Header().Add(headers.XInitialURI, r.URL.RequestURI())
}

// MyPluginAuthCheck does custom auth and will be used as
// "auth_check" custom MW
func MyPluginAuthCheck(rw http.ResponseWriter, r *http.Request) {

	fmt.Println("AUTH")

	// perform auth (only one token "abc" is allowed)
	token := r.Header.Get(headers.Authorization)
	if token != "abc" {
		rw.Header().Add(headers.XAuthResult, "failed")
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	// create session
	session := &user.SessionState{
		OrgID: "default",
		Alias: "abc-session",
	}
	ctx.SetSession(r, session, token, true)

	rw.Header().Add(headers.XAuthResult, "OK")
}

// MyPluginPostKeyAuth checks if session is present, adds custom header with session-alias
// and will be used as "post_key_auth" custom MW
func MyPluginPostKeyAuth(rw http.ResponseWriter, r *http.Request) {
	session := ctx.GetSession(r)
	if session == nil {
		rw.Header().Add(headers.XSessionAlias, "not found")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	rw.Header().Add(headers.XSessionAlias, session.Alias)
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

	rw.Header().Set(headers.ContentType, headers.ApplicationJSON)
	rw.WriteHeader(http.StatusOK)
	rw.Write(jsonData)
}

// MyPluginResponse intercepts response from upstream which we can then manipulate
func MyPluginResponse(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) {
	if ses == nil {
		rw.Header().Add(headers.XSessionAlias, "not found")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	res.Header.Add("X-Response-Added", ses.Alias)
}

func main() {}

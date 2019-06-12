package main

import (
	"encoding/json"
	"net/http"

	"github.com/TykTechnologies/tyk/ctx"
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

	rw.Header().Add("X-Initial-URI", r.URL.RequestURI())
}

// MyPluginAuthCheck does custom auth and will be used as
// "auth_check" custom MW
func MyPluginAuthCheck(rw http.ResponseWriter, r *http.Request) {
	// perform auth (only one token "abc" is allowed)
	token := r.Header.Get("Authorization")
	if token != "abc" {
		rw.Header().Add("X-Auth-Result", "failed")
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	// create session
	session := &user.SessionState{
		OrgID: "default",
		Alias: "abc-session",
	}
	ctx.SetSession(r, session, token, true)

	rw.Header().Add("X-Auth-Result", "OK")
}

// MyPluginPostKeyAuth checks if session is present, adds custom header with session-alias
// and will be used as "post_key_auth" custom MW
func MyPluginPostKeyAuth(rw http.ResponseWriter, r *http.Request) {
	session := ctx.GetSession(r)
	if session == nil {
		rw.Header().Add("X-Session-Alias", "not found")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	rw.Header().Add("X-Session-Alias", session.Alias)
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

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	rw.Write(jsonData)
}

func main() {}

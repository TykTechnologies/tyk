package main

import (
	"fmt"
	"net/http"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/log"
	"github.com/TykTechnologies/tyk/user"
)

var logger = log.Get()

func getSessionByKey(key string) *user.SessionState {
	// here goes our logic to check if passed API key is valid and appropriate key session can be retrieved

	// perform auth (only one token "abc" is allowed)
	if key != "abc" {
		return nil
	}

	// return session
	return &user.SessionState{
		OrgID: "default",
		Alias: "abc-session",
	}
}

func Authenticate(rw http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Authorization")
	fmt.Println("got key ", key)
	session := getSessionByKey(key)
	if session == nil {
		// auth failed, reply with 403
		rw.WriteHeader(http.StatusForbidden)
		rw.Write([]byte("auth failed"))
		return
	}

	// auth was successful, add session and key to request's context so other middlewares can use it
	ctx.SetSession(r, session, true)
	newSession := ctx.GetSession(r)
	fmt.Println("session", newSession)
}

// AddHelloWorldHeader adds custom "Hello: World" header to the request
func AddHelloWorldHeader(rw http.ResponseWriter, r *http.Request) {
	r.Header.Add("Hello", "World")
}

func PreRequestLogger(rw http.ResponseWriter, r *http.Request) {
	logger.Info("request received with url ", r.URL.Path)
}

func AddResponseHeader(rw http.ResponseWriter, res *http.Response, req *http.Request) {
	res.Header.Add("Foo", "Bar")
}

// Called once plugin is loaded, this is where we put all initialization work for plugin
// i.e. setting exported functions, setting up connection pool to storage and etc.
func init() {
	logger.Info("Initialising Example Go Plugin")
}

func main() {}

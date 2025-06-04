package httputil

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// CORSHeaders is a list of CORS headers.
var CORSHeaders = []string{
	"Access-Control-Allow-Origin",
	"Access-Control-Expose-Headers",
	"Access-Control-Max-Age",
	"Access-Control-Allow-Credentials",
	"Access-Control-Allow-Methods",
	"Access-Control-Allow-Headers",
}

// AuthHeader will take username and password and return
// "Basic " + base64 encoded `username:password` for use
// in an Authorization header.
func AuthHeader(username, password string) string {
	toEncode := strings.Join([]string{username, password}, ":")
	encodedPass := base64.StdEncoding.EncodeToString([]byte(toEncode))
	return fmt.Sprintf("Basic %s", encodedPass)
}

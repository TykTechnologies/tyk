package proxy

import "net/http"

type UpstreamAuthProvider interface {
	Fill(r *http.Request)
}

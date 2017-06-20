package main

import (
	"net/http"
	"sync"

	"github.com/gorilla/mux"
)

type RouteProcessor func(*mux.Router)

type routerSwapper struct {
	pre  []RouteProcessor
	post []RouteProcessor
	mu   sync.Mutex
	root *mux.Router
}

func (rs *routerSwapper) Build() (muxer *mux.Router) {
	muxer = mux.NewRouter().SkipClean(config.HttpServerOptions.SkipURLCleaning)
	for _, f := range rs.pre {
		f(muxer)
	}

	return
}

func (rs *routerSwapper) Swap(muxer *mux.Router) {
	for _, f := range rs.post {
		f(muxer)
	}

	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.root = muxer
}

func (rs *routerSwapper) Current() *mux.Router {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.root
}

func (rs *routerSwapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rs.Current().ServeHTTP(w, r)
}

func (rs *routerSwapper) PreProcess(rif RouteProcessor) {
	rs.pre = append(rs.pre, rif)
}

func (rs *routerSwapper) PostProcess(rif RouteProcessor) {
	rs.post = append(rs.post, rif)
}

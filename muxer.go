package main

import (
	"net/http"
	"sync"

	"github.com/gorilla/mux"
)

type routerSwapper struct {
	mu sync.Mutex
	root *mux.Router
}

func (rs *routerSwapper) Swap(newRouter *mux.Router) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.root = newRouter
}

func (rs *routerSwapper) Current() *mux.Router {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.root
}

func (rs *routerSwapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rs.Current().ServeHTTP(w, r)
}

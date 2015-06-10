package main

import (
	"net/http"
)

type TykResponseHandler interface {
	HandleResponse(http.ResponseWriter, *http.Response, *SessionState)
}

type ResponseChain struct{}

func (r ResponseChain) Go(chain *[]TykResponseHandler, rw http.ResponseWriter, res *http.Response, ses *SessionState) {
	for _, rh := range *chain {
		rh.HandleResponse(rw, res, ses)
	}
}

type TestHandler struct{}

func (t TestHandler) HandleResponse(http.ResponseWriter, *http.Response, *SessionState) {
	log.Warning("Hi there")
}

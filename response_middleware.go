package main

import (
	"net/http"
	"errors"
)

var RESPONSE_PROCESSORS map[string]TykResponseHandler = map[string]TykResponseHandler{
	"header_injector": HeaderInjector{},
}

type TykResponseHandler interface {
	HandleResponse(http.ResponseWriter, *http.Response, *SessionState) error
	New(interface{}, *APISpec) (TykResponseHandler, error)
}

func GetResponseProcessorByName(name string) (TykResponseHandler, error)   {
	processor, ok := RESPONSE_PROCESSORS[name]
	if !ok {
		return nil, errors.New("Not found")
	}

	return processor, nil

}

type ResponseChain struct{}

func (r ResponseChain) Go(chain *[]TykResponseHandler, rw http.ResponseWriter, res *http.Response, ses *SessionState) error {
	for _, rh := range *chain {
		mwErr := rh.HandleResponse(rw, res, ses)
		if mwErr != nil {
			return mwErr
		}
	}

	return nil
}


package main

import (
	"net/http"
	"errors"
	"labix.org/v2/mgo/bson"
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

type HeaderInjectorOptions struct {
	HeaderMap map[string]string
}

type HeaderInjector struct{
	Spec *APISpec
	config HeaderInjectorOptions
}

func (h HeaderInjector) New(c interface{}, spec *APISpec) (TykResponseHandler, error) {
	thisHandler := HeaderInjector{}
	switch c.(type) {
	case bson.M:
		thisHandler.config = HeaderInjectorOptions{}
		thisHandler.config.HeaderMap = make(map[string]string)
		m := c.(bson.M)["HeaderMap"].(bson.M)
		for h, v := range(m){
			thisHandler.config.HeaderMap[h] = v.(string)
		}
	default: 
		// This probably wont work
		thisHandler.config = c.(HeaderInjectorOptions)
	}
	
	thisHandler.Spec = spec

	return thisHandler, nil
}

func (h HeaderInjector) HandleResponse(http.ResponseWriter, *http.Response, *SessionState) error {
	log.Warning("Hi there")
	log.Warning(h.config.HeaderMap)
	return nil
}

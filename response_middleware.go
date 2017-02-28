package main

import (
	"errors"
	"net/http"
)

var responseProcessors = map[string]TykResponseHandler{
	"header_injector":         HeaderInjector{},
	"response_body_transform": ResponseTransformMiddleware{},
	"header_transform":        HeaderTransform{},
}

type TykResponseHandler interface {
	HandleResponse(http.ResponseWriter, *http.Response, *http.Request, *SessionState) error
	New(interface{}, *APISpec) (TykResponseHandler, error)
}

func GetResponseProcessorByName(name string) (TykResponseHandler, error) {
	processor, ok := responseProcessors[name]
	if !ok {
		return nil, errors.New("Not found")
	}

	return processor, nil

}

type ResponseChain struct{}

func (r ResponseChain) Go(chain []TykResponseHandler, rw http.ResponseWriter, res *http.Response, req *http.Request, ses *SessionState) error {
	for _, rh := range chain {
		if err := rh.HandleResponse(rw, res, req, ses); err != nil {
			return err
		}
	}
	return nil
}

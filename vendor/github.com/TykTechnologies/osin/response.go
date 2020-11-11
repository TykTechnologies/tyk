package osin

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// Data for response output
type ResponseData map[string]interface{}

// Response type enum
type ResponseType int

const (
	DATA ResponseType = iota
	REDIRECT
)

// Server response
type Response struct {
	Type               ResponseType
	StatusCode         int
	StatusText         string
	ErrorStatusCode    int
	URL                string
	Output             ResponseData
	Headers            http.Header
	IsError            bool
	ErrorId            string
	InternalError      error
	RedirectInFragment bool

	// Storage to use in this response - required
	Storage Storage
}

func NewResponse(storage Storage) *Response {
	r := &Response{
		Type:            DATA,
		StatusCode:      200,
		ErrorStatusCode: 200,
		Output:          make(ResponseData),
		Headers:         make(http.Header),
		IsError:         false,
		Storage:         storage.Clone(),
	}
	r.Headers.Add(
		"Cache-Control",
		"no-cache, no-store, max-age=0, must-revalidate",
	)
	r.Headers.Add("Pragma", "no-cache")
	r.Headers.Add("Expires", "Fri, 01 Jan 1990 00:00:00 GMT")
	return r
}

// SetError sets an error id and description on the Response
// state and uri are left blank
func (r *Response) SetError(id string, description string) {
	r.SetErrorUri(id, description, "", "")
}

// SetErrorState sets an error id, description, and state on the Response
// uri is left blank
func (r *Response) SetErrorState(id string, description string, state string) {
	r.SetErrorUri(id, description, "", state)
}

// SetErrorUri sets an error id, description, state, and uri on the Response
func (r *Response) SetErrorUri(id string, description string, uri string, state string) {
	// get default error message
	if description == "" {
		description = deferror.Get(id)
	}

	// set error parameters
	r.IsError = true
	r.ErrorId = id
	r.StatusCode = r.ErrorStatusCode
	if r.StatusCode != 200 {
		r.StatusText = description
	} else {
		r.StatusText = ""
	}
	r.Output = make(ResponseData) // clear output
	r.Output["error"] = id
	r.Output["error_description"] = description
	if uri != "" {
		r.Output["error_uri"] = uri
	}
	if state != "" {
		r.Output["state"] = state
	}
}

// SetRedirect changes the response to redirect to the given url
func (r *Response) SetRedirect(url string) {
	// set redirect parameters
	r.Type = REDIRECT
	r.URL = url
}

// SetRedirectFragment sets redirect values to be passed in fragment instead of as query parameters
func (r *Response) SetRedirectFragment(f bool) {
	r.RedirectInFragment = f
}

// GetRedirectUrl returns the redirect url with all query string parameters
func (r *Response) GetRedirectUrl() (string, error) {
	if r.Type != REDIRECT {
		return "", errors.New("Not a redirect response")
	}

	u, err := url.Parse(r.URL)
	if err != nil {
		return "", err
	}

	var q url.Values
	if r.RedirectInFragment {
		// start with empty set for fragment
		q = url.Values{}
	} else {
		// add parameters to existing query
		q = u.Query()
	}

	// add parameters
	for n, v := range r.Output {
		q.Set(n, fmt.Sprint(v))
	}

	// https://tools.ietf.org/html/rfc6749#section-4.2.2
	// Fragment should be encoded as application/x-www-form-urlencoded (%-escaped, spaces are represented as '+')
	// The stdlib URL#String() doesn't make that easy to accomplish, so build this ourselves
	if r.RedirectInFragment {
		u.Fragment = ""
		redirectURI := u.String() + "#" + q.Encode()
		return redirectURI, nil
	}

	// Otherwise, update the query and encode normally
	u.RawQuery = q.Encode()
	u.Fragment = ""
	return u.String(), nil
}

func (r *Response) Close() {
	r.Storage.Close()
}

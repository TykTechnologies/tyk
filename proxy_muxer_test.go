package main

import (
	"testing"

	"github.com/TykTechnologies/tyk/test"
)

func TestMultiPortHTTP(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	t.Run("Multiple same port", func(t *testing.T) {
		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test1"
		}, func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test2"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/test1", Code: 200},
			{Path: "/test2", Code: 200},
		}...)
	})

	t.Run("Multiple different port", func(t *testing.T) {
		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test1"
		}, func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test2"
			spec.Proxy.ListenPort = 30001
		})

		ts.Run(t, []test.TestCase{
			{Path: "/test1", Code: 200},
			{URI: "http://localhost:30001/test2", Code: 200},
		}...)
	})
}

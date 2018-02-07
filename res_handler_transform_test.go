package main

import (
	"encoding/base64"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
)

func TestTransformResponseWithURLRewrite(t *testing.T) {
	transformResponseConf := apidef.TemplateMeta{
		Path:   "get",
		Method: "GET",
		TemplateData: apidef.TemplateData{
			Mode:           "blob",
			TemplateSource: base64.StdEncoding.EncodeToString([]byte(`{"http_method":"{{.Method}}"}`)),
		},
	}

	urlRewriteConf := apidef.URLRewriteMeta{
		Path:         "abc",
		Method:       "GET",
		MatchPattern: "abc",
		RewriteTo:    "get",
	}

	responseProcessorConf := []apidef.ResponseProcessor{{Name: "response_body_transform"}}

	t.Run("Transform without rewrite", func(t *testing.T) {
		ts := newTykTestServer()
		defer ts.Close()

		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.ResponseProcessors = responseProcessorConf
			updateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.ExtendedPaths.TransformResponse = []apidef.TemplateMeta{transformResponseConf}
			})
		})

		ts.Run(t, test.TestCase{
			Path: "/get", Code: 200, BodyMatch: `{"http_method":"GET"}`,
		})
	})

	t.Run("Transform path equals rewrite to ", func(t *testing.T) {
		ts := newTykTestServer()
		defer ts.Close()

		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.ResponseProcessors = responseProcessorConf

			updateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.ExtendedPaths.TransformResponse = []apidef.TemplateMeta{transformResponseConf}
				v.ExtendedPaths.URLRewrite = []apidef.URLRewriteMeta{urlRewriteConf}
			})
		})

		ts.Run(t, test.TestCase{
			Path: "/get", Code: 200, BodyMatch: `{"http_method":"GET"}`,
		})
	})

	t.Run("Transform path equals rewrite path", func(t *testing.T) {
		ts := newTykTestServer()
		defer ts.Close()

		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.ResponseProcessors = responseProcessorConf

			transformResponseConf.Path = "abc"

			updateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.ExtendedPaths.TransformResponse = []apidef.TemplateMeta{transformResponseConf}
				v.ExtendedPaths.URLRewrite = []apidef.URLRewriteMeta{urlRewriteConf}
			})
		})

		ts.Run(t, test.TestCase{
			Path: "/abc", Code: 200, BodyMatch: `{"http_method":"GET"}`,
		})
	})
}

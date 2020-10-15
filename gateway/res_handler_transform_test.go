package gateway

import (
	"encoding/base64"
	"testing"

	"github.com/TykTechnologies/tyk/v3/apidef"
	"github.com/TykTechnologies/tyk/v3/test"
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
		ts := StartTest()
		defer ts.Close()

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.ResponseProcessors = responseProcessorConf
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.ExtendedPaths.TransformResponse = []apidef.TemplateMeta{transformResponseConf}
			})
		})

		ts.Run(t, test.TestCase{
			Path: "/get", Code: 200, BodyMatch: `{"http_method":"GET"}`,
		})
	})

	t.Run("Transform path equals rewrite to ", func(t *testing.T) {
		ts := StartTest()
		defer ts.Close()

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.ResponseProcessors = responseProcessorConf

			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.ExtendedPaths.TransformResponse = []apidef.TemplateMeta{transformResponseConf}
				v.ExtendedPaths.URLRewrite = []apidef.URLRewriteMeta{urlRewriteConf}
			})
		})

		ts.Run(t, test.TestCase{
			Path: "/get", Code: 200, BodyMatch: `{"http_method":"GET"}`,
		})
	})

	t.Run("Transform path equals rewrite path", func(t *testing.T) {
		ts := StartTest()
		defer ts.Close()

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.ResponseProcessors = responseProcessorConf

			transformResponseConf.Path = "abc"

			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.ExtendedPaths.TransformResponse = []apidef.TemplateMeta{transformResponseConf}
				v.ExtendedPaths.URLRewrite = []apidef.URLRewriteMeta{urlRewriteConf}
			})
		})

		ts.Run(t, test.TestCase{
			Path: "/abc", Code: 200, BodyMatch: `{"http_method":"GET"}`,
		})
	})
}

func TestTransformResponse_ContextVars(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	transformResponseConf := apidef.TemplateMeta{
		Path:   "get",
		Method: "GET",
		TemplateData: apidef.TemplateData{
			Mode:           "blob",
			TemplateSource: base64.StdEncoding.EncodeToString([]byte(`{"foo":"{{._tyk_context.headers_Foo}}"}`)),
		},
	}

	responseProcessorConf := []apidef.ResponseProcessor{{Name: "response_body_transform"}}

	// When Context Vars are disabled
	BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.ResponseProcessors = responseProcessorConf
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			v.ExtendedPaths.TransformResponse = []apidef.TemplateMeta{transformResponseConf}
		})
	})

	ts.Run(t, test.TestCase{
		Headers: map[string]string{"Foo": "Bar"}, Path: "/get", Code: 200, BodyMatch: `{"foo":"<no value>"}`,
	})

	// When Context Vars are enabled
	BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.EnableContextVars = true
		spec.ResponseProcessors = responseProcessorConf
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			v.ExtendedPaths.TransformResponse = []apidef.TemplateMeta{transformResponseConf}
		})
	})

	ts.Run(t, test.TestCase{
		Headers: map[string]string{"Foo": "Bar"}, Path: "/get", Code: 200, BodyMatch: `{"foo":"Bar"}`,
	})
}

func TestTransformResponse_WithCache(t *testing.T) {
	const path = "/get"

	ts := StartTest()
	defer ts.Close()

	transformResponseConf := apidef.TemplateMeta{
		Path:   path,
		Method: "GET",
		TemplateData: apidef.TemplateData{
			Mode:           "blob",
			TemplateSource: base64.StdEncoding.EncodeToString([]byte(`{"foo":"{{._tyk_context.headers_Foo}}"}`)),
		},
	}
	responseProcessorConf := []apidef.ResponseProcessor{{Name: "response_body_transform"}}

	createAPI := func(withCache bool) {
		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.CacheOptions.CacheTimeout = 60
			spec.EnableContextVars = true
			spec.CacheOptions.EnableCache = withCache
			spec.ResponseProcessors = responseProcessorConf
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.ExtendedPaths.TransformResponse = []apidef.TemplateMeta{transformResponseConf}
				v.ExtendedPaths.Cached = []string{path}
			})
		})

	}

	// without cache
	createAPI(false)

	ts.Run(t, []test.TestCase{
		{Path: path, Headers: map[string]string{"Foo": "Bar"}, Code: 200, BodyMatch: `{"foo":"Bar"}`},
		{Path: path, Headers: map[string]string{"Foo": "Bar2"}, Code: 200, BodyMatch: `{"foo":"Bar2"}`},
	}...)

	// with cache
	createAPI(true)

	ts.Run(t, []test.TestCase{
		{Path: path, Headers: map[string]string{"Foo": "Bar"}, Code: 200, BodyMatch: `{"foo":"Bar"}`},  // Returns response and caches it
		{Path: path, Headers: map[string]string{"Foo": "Bar2"}, Code: 200, BodyMatch: `{"foo":"Bar"}`}, // Returns cached response directly
	}...)

}

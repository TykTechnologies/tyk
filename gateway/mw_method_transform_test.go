package gateway

import (
	"testing"

	"github.com/TykTechnologies/tyk/v3/apidef"
	"github.com/TykTechnologies/tyk/v3/test"
)

func TestMethodTransform(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	t.Run("Using URL rewrite", func(t *testing.T) {

		methodTransform := apidef.MethodTransformMeta{}
		methodTransform.Path = "/get"
		methodTransform.Method = "GET"
		methodTransform.ToMethod = "POST"

		urlRewrite := apidef.URLRewriteMeta{}
		urlRewrite.Path = "/get"
		urlRewrite.Method = "GET"
		urlRewrite.MatchPattern = "/get(.*)"
		urlRewrite.RewriteTo = "/post$1"

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.UseExtendedPaths = true
				v.ExtendedPaths.MethodTransforms = append(v.ExtendedPaths.MethodTransforms, methodTransform)
				v.ExtendedPaths.URLRewrite = append(v.ExtendedPaths.URLRewrite, urlRewrite)
			})
		})

		ts.Run(t, []test.TestCase{
			{Method: "GET", Path: "/get", BodyMatch: `"Url":"/post"`},

			{Method: "GET", Path: "/get?a=b", BodyMatch: `"Method":"POST"`},
		}...)
	})

	t.Run("Using cache", func(t *testing.T) {
		methodTransform := apidef.MethodTransformMeta{}
		methodTransform.Path = "/testing"
		methodTransform.Method = "GET"
		methodTransform.ToMethod = "POST"

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.CacheOptions = apidef.CacheOptions{
				CacheTimeout: 120,
				EnableCache:  true,
			}
			spec.Proxy.ListenPath = "/"
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.UseExtendedPaths = true
				v.ExtendedPaths.Cached = []string{"/testing"}
				v.ExtendedPaths.MethodTransforms = append(v.ExtendedPaths.MethodTransforms, methodTransform)
			})
		})

		headerCache := map[string]string{"x-tyk-cached-response": "1"}

		ts.Run(t, []test.TestCase{
			{Method: "GET", Path: "/testing", HeadersNotMatch: headerCache, BodyMatch: `"Method":"POST"`},
			{Method: "GET", Path: "/testing", HeadersMatch: headerCache, BodyMatch: `"Method":"POST"`},
			{Method: "POST", Path: "/testing", HeadersNotMatch: headerCache},
			{Method: "GET", Path: "/testing", HeadersMatch: headerCache},
		}...)
	})
}

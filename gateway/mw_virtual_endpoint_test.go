package gateway_test

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/user"

	"github.com/TykTechnologies/tyk/test"
)

const virtTestJS = `
function testVirtData(request, session, config) {
	var resp = {
		Body: "foobar",
		Headers: {
			"data-foo": config.config_data.foo,
			"data-bar-y": config.config_data.bar.y.toString(),
			"x-tyk-cache-action-set": "1",
			"x-tyk-cache-action-set-ttl": "10",
		},
		Code: 202
	}
	return TykJsResponse(resp, session.meta_data)
}
`

func TestVirtualEndpoint(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.TestPrepareVirtualEndpoint(virtTestJS, "GET", "/virt1",
		proxyOnErrorDisabled, keylessAuthEnabled, cacheEnabled, false)

	_, _ = ts.Run(t,
		test.TestCase{
			Path:      "/virt1",
			Code:      202,
			BodyMatch: "foobar",
			HeadersNotMatch: map[string]string{
				CachedResponseHeader: "1",
			},
			HeadersMatch: map[string]string{
				"data-foo":   "x",
				"data-bar-y": "3",
			},
		},
		test.TestCase{
			Path:      "/virt1",
			Code:      202,
			BodyMatch: "foobar",
			HeadersMatch: map[string]string{
				"data-foo":           "x",
				"data-bar-y":         "3",
				CachedResponseHeader: "1",
			},
		},
	)
}

func TestVirtualEndpointNotCached(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.TestPrepareVirtualEndpoint(virtTestJS, "GET", "/virt",
		proxyOnErrorDisabled, keylessAuthEnabled, cacheDisabled, false)

	_, _ = ts.Run(t,
		test.TestCase{
			Path:      "/virt",
			Code:      202,
			BodyMatch: "foobar",
			HeadersNotMatch: map[string]string{
				CachedResponseHeader: "1",
			},
			HeadersMatch: map[string]string{
				"data-foo":   "x",
				"data-bar-y": "3",
			},
		},
		test.TestCase{
			Path:      "/virt",
			Code:      202,
			BodyMatch: "foobar",
			HeadersNotMatch: map[string]string{
				CachedResponseHeader: "1",
			},
			HeadersMatch: map[string]string{
				"data-foo":   "x",
				"data-bar-y": "3",
			},
		},
	)
}

func TestVirtualEndpoint500(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	testErrorResponse(ts, t, cacheEnabled)
}

func TestVirtualEndpoint500NotCached(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	testErrorResponse(ts, t, cacheDisabled)
}

func testErrorResponse(ts *Test, t *testing.T, cache bool) {
	ts.TestPrepareVirtualEndpoint("abc", "GET", "/abc",
		proxyOnErrorDisabled, keylessAuthEnabled, cache, false)

	_, _ = ts.Run(t,
		test.TestCase{
			Path: "/abc",
			Code: http.StatusInternalServerError,
			HeadersNotMatch: map[string]string{
				CachedResponseHeader: "1",
			},
		},
		test.TestCase{
			Path: "/abc",
			Code: http.StatusInternalServerError,
			HeadersNotMatch: map[string]string{
				CachedResponseHeader: "1",
			},
		},
	)
}

func TestVirtualEndpointSessionMetadata(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	_, key := ts.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{"test": {
			APIID: "test", Versions: []string{"v1"},
		}}
		s.MetaData = map[string]interface{}{
			"tyk_developer_id":       "5f11cc1ba4b16a176b4a6735",
			"tyk_key_request_fields": map[string]string{"key": "value"},
			"tyk_user_fields":        map[string]string{"key": "value"},
		}
	})

	ts.TestPrepareVirtualEndpoint(virtTestJS, "GET", "/abc",
		proxyOnErrorDisabled, keylessAuthDisabled, cacheEnabled, false)

	_, _ = ts.Run(t,
		test.TestCase{
			Path:    "/abc",
			Headers: map[string]string{"Authorization": key},
			Code:    http.StatusAccepted,
		},
		test.TestCase{
			Path:    "/abc",
			Headers: map[string]string{"Authorization": key},
			Code:    http.StatusAccepted,
		},
	)
}

func BenchmarkVirtualEndpoint(b *testing.B) {
	b.ReportAllocs()

	ts := StartTest(nil)
	defer ts.Close()

	ts.TestPrepareVirtualEndpoint(virtTestJS, "GET", "/virt",
		proxyOnErrorEnabled, keylessAuthEnabled, cacheEnabled, false)

	for i := 0; i < b.N; i++ {
		_, _ = ts.Run(b, test.TestCase{
			Path:      "/virt",
			Code:      202,
			BodyMatch: "foobar",
			HeadersMatch: map[string]string{
				"data-foo":   "x",
				"data-bar-y": "3",
			},
		})
	}
}

func TestVirtualEndpointDisabled(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.TestPrepareVirtualEndpoint(virtTestJS, "GET", "/virt2",
		proxyOnErrorDisabled, keylessAuthEnabled, false, true)

	_, _ = ts.Run(t,
		test.TestCase{
			Path:         "/virt2",
			BodyNotMatch: "foobar",
			HeadersNotMatch: map[string]string{
				"data-foo":   "x",
				"data-bar-y": "3",
			},
		},
	)
}

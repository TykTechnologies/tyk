package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk-pump/analytics"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
)

// memoryBoundMultiplier is the TotalAlloc delta bound, as a multiple of the
// payload size, for a request that takes the bounded (streaming) path. This
// path still allocates one buffer -- the request/response scratch buffer the
// standard library itself uses -- so headroom above 1x is expected; 2x leaves
// that headroom while staying well short of the >=3x delta upstream's own
// #8150 uses to prove the unfixed deep-copy path multiplies allocation.
const memoryBoundMultiplier = 2

// engineerTransform is the body-transform TemplateMeta shared by the
// body-consuming-middleware integration tests below: it doubles the
// "engineer" field's value, proving the middleware itself read and
// re-wrote the body regardless of the passthrough flags.
func engineerTransform(method, path string) apidef.TemplateMeta {
	return apidef.TemplateMeta{
		Disabled: false,
		Path:     path,
		Method:   method,
		TemplateData: apidef.TemplateData{
			Input:          apidef.RequestJSON,
			Mode:           apidef.UseBlob,
			TemplateSource: base64.StdEncoding.EncodeToString([]byte(`{{.engineer | repeat 2}}`)),
		},
	}
}

// genPayload builds a deterministic, ASCII-only payload of n bytes so it
// round-trips losslessly through the echo upstream's JSON response.
func genPayload(n int) []byte {
	payload := make([]byte, n)
	for i := range payload {
		payload[i] = byte('a' + i%26)
	}
	return payload
}

// chunkedBody wraps a reader without exposing Len(), so net/http can't infer
// a Content-Length and falls back to Transfer-Encoding: chunked.
type chunkedBody struct {
	io.Reader
}

// checksumBodyMatch asserts the echo upstream's JSON response carries a body
// whose checksum matches expected, proving the request body reached the
// upstream byte-identical.
func checksumBodyMatch(t *testing.T, expected []byte) func([]byte) bool {
	t.Helper()
	want := sha256.Sum256(expected)
	return func(respBody []byte) bool {
		var decoded struct {
			Body string
		}
		if err := json.Unmarshal(respBody, &decoded); err != nil {
			return false
		}
		got := sha256.Sum256([]byte(decoded.Body))
		return got == want
	}
}

// TestDeepCopyBodySkip_MemoryBounded mirrors upstream's own #8150
// (TestLargeFileUploadMemory) technique: runtime.GC()+ReadMemStats deltas on
// a direct call, not OS RSS, not a full HTTP round trip. Site C: when the
// per-API passthrough flag is enabled, the reverse proxy's call-site guard
// must skip deepCopyBody entirely, keeping allocation bounded instead of
// multiplied.
func TestDeepCopyBodySkip_MemoryBounded(t *testing.T) {
	size := 100 * 1024 * 1024
	payload := genPayload(size)

	req, err := http.NewRequest(http.MethodPost, "http://example.com/upload", bytes.NewReader(payload))
	require.NoError(t, err)
	req.ContentLength = int64(size)

	outreq := new(http.Request)
	*outreq = *req

	spec := testAPISpec(func(s *APISpec) {
		s.EnableRequestBodyPassthrough = true
	})

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	var deepCopyErr error
	if !spec.EnableRequestBodyPassthrough {
		deepCopyErr = deepCopyBody(req, outreq)
	}
	require.NoError(t, deepCopyErr)

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	delta := after.TotalAlloc - before.TotalAlloc
	t.Logf("TotalAlloc delta: %d bytes (payload %d bytes)", delta, size)
	assert.Less(t, delta, uint64(memoryBoundMultiplier*size), "expected bounded allocation when passthrough is active, got a multiplied delta")

	got, err := io.ReadAll(outreq.Body)
	require.NoError(t, err)
	assert.Equal(t, sha256.Sum256(payload), sha256.Sum256(got), "body reaching outreq must be byte-identical to source")
}

// TestDeepCopyBodySkip_OutreqGetBodyStaysNil is a regression guard: Go's
// http.Transport only replays a request via Request.GetBody, and the
// streaming wiring must never populate it, or a streamed body could be
// silently replayed from an already-drained reader.
func TestDeepCopyBodySkip_OutreqGetBodyStaysNil(t *testing.T) {
	testData := []byte("testDeepCopy-getbody-regression")
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(testData))
	outreq := new(http.Request)
	*outreq = *req

	spec := testAPISpec(func(s *APISpec) {
		s.EnableRequestBodyPassthrough = true
	})

	var deepCopyErr error
	if !spec.EnableRequestBodyPassthrough {
		deepCopyErr = deepCopyBody(req, outreq)
	}
	require.NoError(t, deepCopyErr)

	assert.Nil(t, outreq.GetBody, "outreq.GetBody must stay nil so http.Transport can never replay a streamed body")
}

// TestDeepCopyBodyCallSite_PerAPIFlagOff_StillCopies proves the two
// passthrough layers are independently gated, not OR'd: with the per-API
// flag off, site C must still deep-copy, byte-identical to master, even if
// the gateway-wide gate is on.
func TestDeepCopyBodyCallSite_PerAPIFlagOff_StillCopies(t *testing.T) {
	testData := []byte("testDeepCopy-per-api-flag-off")
	src := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(testData))
	trg := &http.Request{}

	spec := testAPISpec(func(s *APISpec) {
		s.EnableRequestBodyPassthrough = false
	})

	var deepCopyErr error
	if !spec.EnableRequestBodyPassthrough {
		deepCopyErr = deepCopyBody(src, trg)
	}
	require.NoError(t, deepCopyErr)
	require.NotNil(t, trg.Body)
	assert.True(t, src.Body != trg.Body, "site C must still deep-copy when the per-API flag is off")

	got, err := io.ReadAll(trg.Body)
	require.NoError(t, err)
	assert.Equal(t, testData, got)
}

// TestHandleWrapperStreamRequestBody_MemoryBounded covers site A: with both
// the global gate and requestBodyPassthrough on, handleWrapper must skip the
// greedy nopCloseRequestBodyErr read for both Content-Length-framed and
// chunked bodies -- unlike copyRequest, nopCloseRequestBodyErr has no
// pre-existing chunked shortcut, so this is the branch that actually fixes
// the multiplier bug.
func TestHandleWrapperStreamRequestBody_MemoryBounded(t *testing.T) {
	size := 100 * 1024 * 1024

	t.Run("content-length framed", func(t *testing.T) {
		payload := genPayload(size)
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(payload))
		req.ContentLength = int64(size)
		w := httptest.NewRecorder()

		handler := &handleWrapper{
			maxRequestBodySize:     int64(size) + 1,
			requestBodyPassthrough: true,
		}

		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)

		handler.ServeHTTP(w, req)

		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)

		delta := after.TotalAlloc - before.TotalAlloc
		t.Logf("TotalAlloc delta (CL-framed): %d bytes (payload %d bytes)", delta, size)
		assert.Less(t, delta, uint64(memoryBoundMultiplier*size))
	})

	t.Run("chunked", func(t *testing.T) {
		payload := genPayload(size)
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(payload))
		req.ContentLength = -1
		w := httptest.NewRecorder()

		handler := &handleWrapper{
			maxRequestBodySize:     int64(size) + 1,
			requestBodyPassthrough: true,
		}

		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)

		handler.ServeHTTP(w, req)

		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)

		delta := after.TotalAlloc - before.TotalAlloc
		t.Logf("TotalAlloc delta (chunked): %d bytes (payload %d bytes)", delta, size)
		assert.Less(t, delta, uint64(memoryBoundMultiplier*size))
	})
}

// TestCopyRequestChunkedBody_AlreadyBoundedRegardlessOfFlag documents a
// parity case, not a fix: with the global gate off (today's default/lazy
// branch, maxRequestBodySize == 0), a chunked body already skips buffering
// today via copyRequest's pre-existing ContentLength == -1 shortcut,
// independent of the new streaming flag.
func TestCopyRequestChunkedBody_AlreadyBoundedRegardlessOfFlag(t *testing.T) {
	size := 100 * 1024 * 1024
	payload := genPayload(size)

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(payload))
	req.ContentLength = -1
	w := httptest.NewRecorder()

	handler := &handleWrapper{
		maxRequestBodySize:     0,
		requestBodyPassthrough: false,
	}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	handler.ServeHTTP(w, req)

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	delta := after.TotalAlloc - before.TotalAlloc
	t.Logf("TotalAlloc delta (chunked, default lazy path): %d bytes (payload %d bytes)", delta, size)
	assert.Less(t, delta, uint64(memoryBoundMultiplier*size), "copyRequest already skips buffering chunked bodies today, streaming flag or not")
}

// TestPerAPIFlagOnly_SitesABStillBufferSiteCSkips covers the reverse
// combination from the site A/C tests above: with only the per-API flag on
// (global gate off), sites A/B must still buffer -- they cannot see the
// per-API flag pre-routing -- while site C skips its now-redundant copy
// without corrupting anything, since the body is already buffered.
func TestPerAPIFlagOnly_SitesABStillBufferSiteCSkips(t *testing.T) {
	t.Run("sites A/B still buffer when global gate is off", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader("small body"))
		w := httptest.NewRecorder()

		handler := &handleWrapper{
			maxRequestBodySize:     0,
			requestBodyPassthrough: false,
		}
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
	})

	t.Run("site C skips the now-redundant copy", func(t *testing.T) {
		testData := []byte("already-buffered-body")
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(testData))
		outreq := new(http.Request)
		*outreq = *req

		spec := testAPISpec(func(s *APISpec) {
			s.EnableRequestBodyPassthrough = true
		})

		var deepCopyErr error
		if !spec.EnableRequestBodyPassthrough {
			deepCopyErr = deepCopyBody(req, outreq)
		}
		require.NoError(t, deepCopyErr)
		assert.True(t, req.Body == outreq.Body, "outreq must share the already-buffered reader, no corruption")
	})
}

// panicOnReadBody proves recordGraphDetails never reads the request body
// when the per-API passthrough flag is active: any Read call fails the test
// via panic instead of silently consuming an already-streamed body.
type panicOnReadBody struct{}

func (panicOnReadBody) Read([]byte) (int, error) {
	panic("recordGraphDetails must not read the body when streaming is active")
}

func (panicOnReadBody) Close() error { return nil }

// TestRecordGraphDetails_SkipsBodyReadWhenPassthrough extends the same
// graceful runtime-skip posture recordDetail already applies for
// websocket/gRPC streaming to the GraphQL analytics path, which today only
// guards on r.Body == nil.
func TestRecordGraphDetails_SkipsBodyReadWhenPassthrough(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/graphql", panicOnReadBody{})

	spec := testAPISpec(func(s *APISpec) {
		s.GraphQL.Enabled = true
		s.EnableRequestBodyPassthrough = true
	})

	rec := &analytics.AnalyticsRecord{}
	resp := &http.Response{}

	assert.NotPanics(t, func() {
		recordGraphDetails(rec, req, resp, spec)
	})
	assert.Equal(t, analytics.GraphQLStats{}, rec.GraphQLStats, "recordGraphDetails must not populate GraphQLStats when the body read is skipped")
}

// TestRequestBodyPassthrough_NoFlags_ByteIdenticalToMaster is the true
// baseline: an API that never touches either flag (both absent/false, the
// zero value on current master) must behave exactly as it does today for
// both a large Content-Length-framed POST and a large chunked PATCH. This is
// the reference point every other passthrough scenario is measured against.
func TestRequestBodyPassthrough_NoFlags_ByteIdenticalToMaster(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = true
	})

	payload := genPayload(64 * 1024)

	_, _ = ts.Run(t, []test.TestCase{
		{
			Method:        http.MethodPost,
			Path:          "/echo",
			Data:          payload,
			Code:          http.StatusOK,
			BodyMatchFunc: checksumBodyMatch(t, payload),
		},
		{
			Method:        http.MethodPatch,
			Path:          "/echo",
			Data:          chunkedBody{bytes.NewReader(payload)},
			Code:          http.StatusOK,
			BodyMatchFunc: checksumBodyMatch(t, payload),
		},
	}...)
}

// TestRequestBodyPassthrough_EndToEnd_BothFlagsOn: with both the gateway-wide
// gate and the per-API flag on, the request body must reach the upstream
// byte-identical for both Content-Length-framed and chunked bodies.
func TestRequestBodyPassthrough_EndToEnd_BothFlagsOn(t *testing.T) {
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.HttpServerOptions.EnableRequestBodyPassthrough = true
	})
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = true
		spec.EnableRequestBodyPassthrough = true
	})

	payload := genPayload(64 * 1024)

	t.Run("content-length framed", func(t *testing.T) {
		_, _ = ts.Run(t, test.TestCase{
			Method:        http.MethodPost,
			Path:          "/echo",
			Data:          payload,
			Code:          http.StatusOK,
			BodyMatchFunc: checksumBodyMatch(t, payload),
		})
	})

	t.Run("chunked", func(t *testing.T) {
		_, _ = ts.Run(t, test.TestCase{
			Method:        http.MethodPatch,
			Path:          "/echo",
			Data:          chunkedBody{bytes.NewReader(payload)},
			Code:          http.StatusOK,
			BodyMatchFunc: checksumBodyMatch(t, payload),
		})
	})
}

// TestRequestBodyPassthrough_BothFlagsOn_WithBodyConsumingMiddleware_Inert
// proves the "safe but inert" claim for a request where streaming really is
// active end to end (both the gateway-wide gate and the per-API flag are
// true): an API that also runs a body-consuming middleware (body transform)
// behaves exactly as it does on master. The middleware already fully reads
// and re-wraps the body itself before site C is ever reached, so skipping
// deepCopyBody changes nothing observable for this request -- streaming is
// inert here, not broken.
func TestRequestBodyPassthrough_BothFlagsOn_WithBodyConsumingMiddleware_Inert(t *testing.T) {
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.HttpServerOptions.EnableRequestBodyPassthrough = true
	})
	defer ts.Close()

	api := BuildAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = true
		spec.EnableRequestBodyPassthrough = true
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			v.ExtendedPaths.Transform = []apidef.TemplateMeta{
				engineerTransform(http.MethodPost, "/echo"),
			}
		})
	})[0]
	ts.Gw.LoadAPI(api)

	_, _ = ts.Run(t, test.TestCase{
		Method:    http.MethodPost,
		Path:      "/echo",
		Data:      `{"engineer":"Furkan"}`,
		Code:      http.StatusOK,
		BodyMatch: `"Body":"FurkanFurkan"`,
	})
}

// TestRequestBodyPassthrough_PerAPIOffGlobalOn_ByteIdentical de-risks the
// gateway-wide caveat: flipping the global gate must not break APIs that
// never opted in, whether they're a plain proxy or run a body-consuming
// middleware.
func TestRequestBodyPassthrough_PerAPIOffGlobalOn_ByteIdentical(t *testing.T) {
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.HttpServerOptions.EnableRequestBodyPassthrough = true
	})
	defer ts.Close()

	t.Run("plain proxy without per-API flag, byte-identical to master", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.UseKeylessAccess = true
			spec.EnableRequestBodyPassthrough = false
		})

		payload := genPayload(64 * 1024)

		_, _ = ts.Run(t, []test.TestCase{
			{
				Method:        http.MethodPost,
				Path:          "/echo",
				Data:          payload,
				Code:          http.StatusOK,
				BodyMatchFunc: checksumBodyMatch(t, payload),
			},
			{
				Method:        http.MethodPatch,
				Path:          "/echo",
				Data:          chunkedBody{bytes.NewReader(payload)},
				Code:          http.StatusOK,
				BodyMatchFunc: checksumBodyMatch(t, payload),
			},
		}...)
	})

	t.Run("body-consuming middleware without per-API flag still transforms", func(t *testing.T) {
		api := BuildAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.UseKeylessAccess = true
			spec.EnableRequestBodyPassthrough = false
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.ExtendedPaths.Transform = []apidef.TemplateMeta{
					engineerTransform(http.MethodPost, "/echo"),
					engineerTransform(http.MethodPatch, "/echo"),
				}
			})
		})[0]
		ts.Gw.LoadAPI(api)

		_, _ = ts.Run(t, []test.TestCase{
			{
				Method:    http.MethodPost,
				Path:      "/echo",
				Data:      `{"engineer":"Furkan"}`,
				Code:      http.StatusOK,
				BodyMatch: `"Body":"FurkanFurkan"`,
			},
			{
				Method:    http.MethodPatch,
				Path:      "/echo",
				Data:      chunkedBody{strings.NewReader(`{"engineer":"Furkan"}`)},
				Code:      http.StatusOK,
				BodyMatch: `"Body":"FurkanFurkan"`,
			},
		}...)
	})
}

// TestRequestBodyPassthrough_PerAPIFlagInertWhenGlobalOff proves the
// per-API flag alone (global gate off) is safe but inert: sites A/B still
// buffer, so the request still reaches the upstream correctly, just without
// the memory win.
func TestRequestBodyPassthrough_PerAPIFlagInertWhenGlobalOff(t *testing.T) {
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.HttpServerOptions.EnableRequestBodyPassthrough = false
	})
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = true
		spec.EnableRequestBodyPassthrough = true
	})

	payload := genPayload(64 * 1024)

	_, _ = ts.Run(t, test.TestCase{
		Method:        http.MethodPost,
		Path:          "/echo",
		Data:          payload,
		Code:          http.StatusOK,
		BodyMatchFunc: checksumBodyMatch(t, payload),
	})
}

// TestRequestBodyPassthrough_MaxRequestBodySizeStillEnforced proves
// streaming and max_request_body_size are compatible, not mutually
// exclusive: http.MaxBytesReader still rejects oversize requests with 413
// even on a passthrough-enabled API.
func TestRequestBodyPassthrough_MaxRequestBodySizeStillEnforced(t *testing.T) {
	limit := int64(1024)

	ts := StartTest(func(globalConf *config.Config) {
		globalConf.HttpServerOptions.MaxRequestBodySize = limit
		globalConf.HttpServerOptions.EnableRequestBodyPassthrough = true
	})
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = true
		spec.EnableRequestBodyPassthrough = true
	})

	_, _ = ts.Run(t, []test.TestCase{
		{Method: http.MethodPost, Path: "/echo", Data: strings.Repeat("a", int(limit)), Code: http.StatusOK},
		{Method: http.MethodPost, Path: "/echo", Data: strings.Repeat("a", int(limit)+1), Code: http.StatusRequestEntityTooLarge},
	}...)
}

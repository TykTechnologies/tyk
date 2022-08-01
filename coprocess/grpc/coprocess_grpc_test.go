package grpc

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"math/rand"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/coprocess"
	"github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

const (
	grpcListenAddr  = ":9999"
	grpcListenPath  = "tcp://127.0.0.1:9999"
	grpcTestMaxSize = 100000000

	testHeaderName  = "Testheader"
	testHeaderValue = "testvalue"
)

type dispatcher struct{}

func (d *dispatcher) grpcError(object *coprocess.Object, errorMsg string) (*coprocess.Object, error) {
	object.Request.ReturnOverrides.ResponseError = errorMsg
	object.Request.ReturnOverrides.ResponseCode = 400
	return object, nil
}

func (d *dispatcher) Dispatch(ctx context.Context, object *coprocess.Object) (*coprocess.Object, error) {
	switch object.HookName {
	case "testPreHook1":
		object.Request.SetHeaders = map[string]string{
			testHeaderName: testHeaderValue,
		}
	case "testPreHook2":
		contentType, found := object.Request.Headers["Content-Type"]
		if !found {
			return d.grpcError(object, "Content Type field not found")
		}
		if strings.Contains(contentType, "json") {
			if len(object.Request.Body) == 0 {
				return d.grpcError(object, "Body field is empty")
			}
			if len(object.Request.RawBody) == 0 {
				return d.grpcError(object, "Raw body field is empty")
			}
			if strings.Compare(object.Request.Body, string(object.Request.Body)) != 0 {
				return d.grpcError(object, "Raw body and body fields don't match")
			}
		} else if strings.Contains(contentType, "multipart") {
			if len(object.Request.Body) != 0 {
				return d.grpcError(object, "Body field isn't empty")
			}
			if len(object.Request.RawBody) == 0 {
				return d.grpcError(object, "Raw body field is empty")
			}
		} else {
			return d.grpcError(object, "Request content type should be either JSON or multipart")
		}
	case "testPostHook1":
		testKeyValue, ok := object.Session.Metadata["testkey"]
		if !ok {
			return d.grpcError(object, "'testkey' not found in session metadata")
		}
		jsonObject := make(map[string]string)
		if err := json.Unmarshal([]byte(testKeyValue), &jsonObject); err != nil {
			return d.grpcError(object, "couldn't decode 'testkey' nested value")
		}
		nestedKeyValue, ok := jsonObject["nestedkey"]
		if !ok {
			return d.grpcError(object, "'nestedkey' not found in JSON object")
		}
		if nestedKeyValue != "nestedvalue" {
			return d.grpcError(object, "'nestedvalue' value doesn't match")
		}
		testKey2Value, ok := object.Session.Metadata["testkey2"]
		if !ok {
			return d.grpcError(object, "'testkey' not found in session metadata")
		}
		if testKey2Value != "testvalue" {
			return d.grpcError(object, "'testkey2' value doesn't match")
		}

		// Check for compatibility (object.Metadata should contain the same keys as object.Session.Metadata)
		for k, v := range object.Metadata {
			sessionKeyValue, ok := object.Session.Metadata[k]
			if !ok {
				return d.grpcError(object, k+" not found in object.Session.Metadata")
			}
			if strings.Compare(sessionKeyValue, v) != 0 {
				return d.grpcError(object, k+" doesn't match value in object.Session.Metadata")
			}
		}
	case "testResponseHook":
		object.Response.RawBody = []byte("newbody")
	}
	return object, nil
}

func (d *dispatcher) DispatchEvent(ctx context.Context, event *coprocess.Event) (*coprocess.EventReply, error) {
	return &coprocess.EventReply{}, nil
}

func newTestGRPCServer() (s *grpc.Server) {
	s = grpc.NewServer(
		grpc.MaxRecvMsgSize(grpcTestMaxSize),
		grpc.MaxSendMsgSize(grpcTestMaxSize),
	)
	coprocess.RegisterDispatcherServer(s, &dispatcher{})
	return s
}

func loadTestGRPCAPIs(s *gateway.Test) {

	s.Gw.BuildAndLoadAPI(func(spec *gateway.APISpec) {
		spec.APIID = "1"
		spec.OrgID = gateway.MockOrgID
		spec.Auth = apidef.AuthConfig{
			AuthHeaderName: "authorization",
		}
		spec.UseKeylessAccess = false
		spec.VersionData = struct {
			NotVersioned   bool                          `bson:"not_versioned" json:"not_versioned"`
			DefaultVersion string                        `bson:"default_version" json:"default_version"`
			Versions       map[string]apidef.VersionInfo `bson:"versions" json:"versions"`
		}{
			NotVersioned: true,
			Versions: map[string]apidef.VersionInfo{
				"v1": {
					Name: "v1",
				},
			},
		}
		spec.Proxy.ListenPath = "/grpc-test-api/"
		spec.Proxy.StripListenPath = true
		spec.CustomMiddleware = apidef.MiddlewareSection{
			Pre: []apidef.MiddlewareDefinition{
				{Name: "testPreHook1"},
			},
			Driver: apidef.GrpcDriver,
		}
	}, func(spec *gateway.APISpec) {
		spec.APIID = "2"
		spec.OrgID = gateway.MockOrgID
		spec.Auth = apidef.AuthConfig{
			AuthHeaderName: "authorization",
		}
		spec.UseKeylessAccess = true
		spec.VersionData = struct {
			NotVersioned   bool                          `bson:"not_versioned" json:"not_versioned"`
			DefaultVersion string                        `bson:"default_version" json:"default_version"`
			Versions       map[string]apidef.VersionInfo `bson:"versions" json:"versions"`
		}{
			NotVersioned: true,
			Versions: map[string]apidef.VersionInfo{
				"v1": {
					Name: "v1",
				},
			},
		}
		spec.Proxy.ListenPath = "/grpc-test-api-2/"
		spec.Proxy.StripListenPath = true
		spec.CustomMiddleware = apidef.MiddlewareSection{
			Pre: []apidef.MiddlewareDefinition{
				{Name: "testPreHook2"},
			},
			Driver: apidef.GrpcDriver,
		}
	}, func(spec *gateway.APISpec) {
		spec.APIID = "3"
		spec.OrgID = "default"
		spec.Auth = apidef.AuthConfig{
			AuthHeaderName: "authorization",
		}
		spec.UseKeylessAccess = false
		spec.VersionData = struct {
			NotVersioned   bool                          `bson:"not_versioned" json:"not_versioned"`
			DefaultVersion string                        `bson:"default_version" json:"default_version"`
			Versions       map[string]apidef.VersionInfo `bson:"versions" json:"versions"`
		}{
			NotVersioned: true,
			Versions: map[string]apidef.VersionInfo{
				"v1": {
					Name: "v1",
				},
			},
		}
		spec.Proxy.ListenPath = "/grpc-test-api-3/"
		spec.Proxy.StripListenPath = true
		spec.CustomMiddleware = apidef.MiddlewareSection{
			Post: []apidef.MiddlewareDefinition{
				{Name: "testPostHook1"},
			},
			Driver: apidef.GrpcDriver,
		}
	},
		func(spec *gateway.APISpec) {
			spec.APIID = "4"
			spec.OrgID = "default"
			spec.Auth = apidef.AuthConfig{
				AuthHeaderName: "authorization",
			}
			spec.UseKeylessAccess = false
			spec.VersionData = struct {
				NotVersioned   bool                          `bson:"not_versioned" json:"not_versioned"`
				DefaultVersion string                        `bson:"default_version" json:"default_version"`
				Versions       map[string]apidef.VersionInfo `bson:"versions" json:"versions"`
			}{
				NotVersioned: true,
				Versions: map[string]apidef.VersionInfo{
					"v1": {
						Name: "v1",
					},
				},
			}
			spec.Proxy.ListenPath = "/grpc-test-api-4/"
			spec.Proxy.StripListenPath = true
			spec.CustomMiddleware = apidef.MiddlewareSection{
				Response: []apidef.MiddlewareDefinition{
					{Name: "testResponseHook"},
				},
				Driver: apidef.GrpcDriver,
			}
		},
		func(spec *gateway.APISpec) {
			spec.APIID = "ignore_plugin"
			spec.OrgID = gateway.MockOrgID
			spec.Auth = apidef.AuthConfig{
				AuthHeaderName: "authorization",
			}
			spec.UseKeylessAccess = false
			spec.EnableCoProcessAuth = true
			spec.VersionData = struct {
				NotVersioned   bool                          `bson:"not_versioned" json:"not_versioned"`
				DefaultVersion string                        `bson:"default_version" json:"default_version"`
				Versions       map[string]apidef.VersionInfo `bson:"versions" json:"versions"`
			}{
				DefaultVersion: "v1",
				Versions: map[string]apidef.VersionInfo{
					"v1": {
						Name:             "v1",
						UseExtendedPaths: true,
						ExtendedPaths: apidef.ExtendedPathsSet{
							Ignored: []apidef.EndPointMeta{
								{
									Path:       "/anything",
									IgnoreCase: true,
									MethodActions: map[string]apidef.EndpointMethodMeta{
										http.MethodGet: {
											Action: apidef.NoAction,
											Code:   http.StatusOK,
										},
									},
								},
							},
						},
					},
				},
			}
			spec.Proxy.ListenPath = "/grpc-test-api-ignore/"
			spec.Proxy.StripListenPath = true
			spec.CustomMiddleware = apidef.MiddlewareSection{
				Driver: apidef.GrpcDriver,
				IdExtractor: apidef.MiddlewareIdExtractor{
					ExtractFrom: apidef.HeaderSource,
					ExtractWith: apidef.ValueExtractor,
					ExtractorConfig: map[string]interface{}{
						"header_name": "Authorization",
					},
				},
			}
		},
	)
}

func startTykWithGRPC() (*gateway.Test, *grpc.Server) {
	// Setup the gRPC server:
	listener, _ := net.Listen("tcp", grpcListenAddr)
	grpcServer := newTestGRPCServer()
	go grpcServer.Serve(listener)

	// Setup Tyk:
	cfg := config.CoProcessConfig{
		EnableCoProcess:     true,
		CoProcessGRPCServer: grpcListenPath,
		GRPCRecvMaxSize:     grpcTestMaxSize,
		GRPCSendMaxSize:     grpcTestMaxSize,
	}
	ts := gateway.StartTest(nil, gateway.TestConfig{
		CoprocessConfig:   cfg,
		EnableTestDNSMock: false,
	})

	// Load test APIs:
	loadTestGRPCAPIs(ts)
	return ts, grpcServer
}

func TestMain(m *testing.M) {
	os.Exit(gateway.InitTestMain(context.Background(), m))
}

func TestGRPCDispatch(t *testing.T) {
	ts, grpcServer := startTykWithGRPC()
	defer ts.Close()
	defer grpcServer.Stop()

	keyID := gateway.CreateSession(ts.Gw, func(s *user.SessionState) {
		s.MetaData = map[string]interface{}{
			"testkey":  map[string]interface{}{"nestedkey": "nestedvalue"},
			"testkey2": "testvalue",
		}
	})
	headers := map[string]string{"authorization": keyID}

	t.Run("Pre Hook with SetHeaders", func(t *testing.T) {
		res, err := ts.Run(t, test.TestCase{
			Path:    "/grpc-test-api/",
			Method:  http.MethodGet,
			Code:    http.StatusOK,
			Headers: headers,
		})
		if err != nil {
			t.Fatalf("Request failed: %s", err.Error())
		}
		data, err := ioutil.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("Couldn't read response body: %s", err.Error())
		}
		var testResponse gateway.TestHttpResponse
		err = json.Unmarshal(data, &testResponse)
		if err != nil {
			t.Fatalf("Couldn't unmarshal test response JSON: %s", err.Error())
		}
		value, ok := testResponse.Headers[testHeaderName]
		if !ok {
			t.Fatalf("Header not found, expecting %s", testHeaderName)
		}
		if value != testHeaderValue {
			t.Fatalf("Header value isn't %s", testHeaderValue)
		}
	})

	t.Run("Pre Hook with UTF-8/non-UTF-8 request data", func(t *testing.T) {
		fileData := gateway.GenerateTestBinaryData()
		var buf bytes.Buffer
		multipartWriter := multipart.NewWriter(&buf)
		file, err := multipartWriter.CreateFormFile("file", "test.bin")
		if err != nil {
			t.Fatalf("Couldn't use multipart writer: %s", err.Error())
		}
		_, err = fileData.WriteTo(file)
		if err != nil {
			t.Fatalf("Couldn't write to multipart file: %s", err.Error())
		}
		field, err := multipartWriter.CreateFormField("testfield")
		if err != nil {
			t.Fatalf("Couldn't use multipart writer: %s", err.Error())
		}
		_, err = field.Write([]byte("testvalue"))
		if err != nil {
			t.Fatalf("Couldn't write to form field: %s", err.Error())
		}
		err = multipartWriter.Close()
		if err != nil {
			t.Fatalf("Couldn't close multipart writer: %s", err.Error())
		}

		ts.Run(t, []test.TestCase{
			{Path: "/grpc-test-api-2/", Code: 200, Data: &buf, Headers: map[string]string{"Content-Type": multipartWriter.FormDataContentType()}},
			{Path: "/grpc-test-api-2/", Code: 200, Data: "{}", Headers: map[string]string{"Content-Type": "application/json"}},
		}...)
	})

	t.Run("Post Hook with metadata", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Path:    "/grpc-test-api-3/",
			Method:  http.MethodGet,
			Code:    http.StatusOK,
			Headers: headers,
		})
	})

	t.Run("Response hook", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Path:      "/grpc-test-api-4/",
			Method:    http.MethodGet,
			Code:      http.StatusOK,
			Headers:   headers,
			BodyMatch: "newbody",
		})
	})

	t.Run("Post Hook with allowed message length", func(t *testing.T) {
		test.Flaky(t)

		s := randStringBytes(20000000)
		ts.Run(t, test.TestCase{
			Path:    "/grpc-test-api-3/",
			Method:  http.MethodGet,
			Code:    http.StatusOK,
			Headers: headers,
			Data:    s,
		})
	})

	t.Run("Post Hook with with unallowed message length", func(t *testing.T) {
		test.Flaky(t)

		s := randStringBytes(150000000)
		ts.Run(t, test.TestCase{
			Path:    "/grpc-test-api-3/",
			Method:  http.MethodGet,
			Code:    http.StatusInternalServerError,
			Headers: headers,
			Data:    s,
		})
	})
}

func BenchmarkGRPCDispatch(b *testing.B) {
	ts, grpcServer := startTykWithGRPC()
	defer ts.Close()
	defer grpcServer.Stop()

	keyID := gateway.CreateSession(ts.Gw)
	headers := map[string]string{"authorization": keyID}

	b.Run("Pre Hook with SetHeaders", func(b *testing.B) {
		path := "/grpc-test-api/"
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ts.Run(b, test.TestCase{
				Path:    path,
				Method:  http.MethodGet,
				Code:    http.StatusOK,
				Headers: headers,
			})
		}
	})
}

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randStringBytes(n int) string {
	return strings.Repeat(string(letters[rand.Intn(len(letters))]), n)
}

func TestGRPCIgnore(t *testing.T) {
	ts, grpcServer := startTykWithGRPC()
	defer ts.Close()
	defer grpcServer.Stop()

	path := "/grpc-test-api-ignore/"

	// no header
	ts.Run(t, test.TestCase{
		Path:   path + "something",
		Method: http.MethodGet,
		Code:   http.StatusBadRequest,
		BodyMatchFunc: func(b []byte) bool {
			return bytes.Contains(b, []byte("Authorization field missing"))
		},
	})

	ts.Run(t, test.TestCase{
		Path:   path + "anything",
		Method: http.MethodGet,
		Code:   http.StatusOK,
	})

	// bad header
	headers := map[string]string{"authorization": "bad"}
	ts.Run(t, test.TestCase{
		Path:    path + "something",
		Method:  http.MethodGet,
		Code:    http.StatusForbidden,
		Headers: headers,
	})

	ts.Run(t, test.TestCase{
		Path:    path + "anything",
		Method:  http.MethodGet,
		Code:    http.StatusOK,
		Headers: headers,
	})
}

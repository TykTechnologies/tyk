// +build coprocess
// +build grpc

package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"mime/multipart"
	"net"
	"net/http"
	"strings"
	"testing"

	"context"

	"google.golang.org/grpc"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/coprocess"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

const (
	grpcListenAddr = ":9999"
	grpcListenPath = "tcp://127.0.0.1:9999"

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
	}
	return object, nil
}

func (d *dispatcher) DispatchEvent(ctx context.Context, event *coprocess.Event) (*coprocess.EventReply, error) {
	return &coprocess.EventReply{}, nil
}

func newTestGRPCServer() (s *grpc.Server) {
	s = grpc.NewServer()
	coprocess.RegisterDispatcherServer(s, &dispatcher{})
	return s
}

func loadTestGRPCAPIs() {
	buildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "1"
		spec.OrgID = mockOrgID
		spec.Auth = apidef.Auth{
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
	}, func(spec *APISpec) {
		spec.APIID = "2"
		spec.OrgID = mockOrgID
		spec.Auth = apidef.Auth{
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
	}, func(spec *APISpec) {
		spec.APIID = "3"
		spec.OrgID = "default"
		spec.Auth = apidef.Auth{
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
	})
}

func startTykWithGRPC() (*tykTestServer, *grpc.Server) {
	// Setup the gRPC server:
	listener, _ := net.Listen("tcp", grpcListenAddr)
	grpcServer := newTestGRPCServer()
	go grpcServer.Serve(listener)

	// Setup Tyk:
	cfg := config.CoProcessConfig{
		EnableCoProcess:     true,
		CoProcessGRPCServer: grpcListenPath,
	}
	ts := newTykTestServer(tykTestServerConfig{coprocessConfig: cfg})

	// Load test APIs:
	loadTestGRPCAPIs()
	return &ts, grpcServer
}

func TestGRPCDispatch(t *testing.T) {
	ts, grpcServer := startTykWithGRPC()
	defer ts.Close()
	defer grpcServer.Stop()

	keyID := createSession(func(s *user.SessionState) {
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
		var testResponse testHttpResponse
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
		fileData := generateTestBinaryData()
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

}

func BenchmarkGRPCDispatch(b *testing.B) {
	ts, grpcServer := startTykWithGRPC()
	defer ts.Close()
	defer grpcServer.Stop()

	keyID := createSession(func(s *user.SessionState) {})
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

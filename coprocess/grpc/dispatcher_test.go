package grpc

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk/coprocess"
)

type dispatcher struct{}

func (d *dispatcher) grpcError(object *coprocess.Object, errorMsg string) (*coprocess.Object, error) {
	object.Request.ReturnOverrides.ResponseError = errorMsg
	object.Request.ReturnOverrides.ResponseCode = 400
	return object, nil
}

func (d *dispatcher) Dispatch(_ context.Context, object *coprocess.Object) (*coprocess.Object, error) {
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
	case "testConfigDataResponseHook":
		if _, ok := object.Spec["config_data"]; ok {
			object.Response.Headers["x-config-data"] = "true"
			object.Response.MultivalueHeaders = append(object.Response.MultivalueHeaders, &coprocess.Header{
				Key:    "x-config-data",
				Values: []string{"true"},
			})
		} else {
			object.Response.Headers["x-config-data"] = "false"
			object.Response.MultivalueHeaders = append(object.Response.MultivalueHeaders, &coprocess.Header{
				Key:    "x-config-data",
				Values: []string{"false"},
			})
		}
	case "testAuthHook1":
		req := object.Request
		token := req.Headers["Authorization"]
		if object.Metadata == nil {
			object.Metadata = map[string]string{}
		}
		object.Metadata["token"] = token
		if token != "abc" {
			return d.grpcError(object, "invalid token")
		}

		session := coprocess.SessionState{
			Rate:                100,
			IdExtractorDeadline: time.Now().Add(2 * time.Second).Unix(),
			Metadata: map[string]string{
				"sessionMetaKey": "customAuthSessionMetaValue",
			},
		}

		object.Session = &session
	}
	return object, nil
}

func (d *dispatcher) DispatchEvent(_ context.Context, _ *coprocess.Event) (*coprocess.EventReply, error) {
	return &coprocess.EventReply{}, nil
}

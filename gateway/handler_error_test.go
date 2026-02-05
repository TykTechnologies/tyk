package gateway

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/test"
)

func (s *Test) TestHandleError_text_xml(t *testing.T) {
	file := filepath.Join(s.Gw.GetConfig().TemplatePath, "error_500.xml")
	xml := `<?xml version = "1.0" encoding = "UTF-8"?>
<error>
	<code>500</code>
	<message>{{.Message}}</message>
</error>`
	err := ioutil.WriteFile(file, []byte(xml), 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file)
	expect := `<?xml version = "1.0" encoding = "UTF-8"?>
<error>
	<code>500</code>
	<message>There was a problem proxying the request</message>
</error>`

	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = "http://localhost:66666"
	})
	ts.Run(t, test.TestCase{
		Path: "/",
		Code: http.StatusInternalServerError,
		Headers: map[string]string{
			header.ContentType: header.TextXML,
		},
		BodyMatchFunc: func(b []byte) bool {
			return strings.TrimSpace(expect) == string(bytes.TrimSpace(b))
		},
	})

	ts.Run(t, test.TestCase{
		Path: "/",
		Code: http.StatusInternalServerError,
		Headers: map[string]string{
			header.ContentType: header.TextXML + "; charset=UTF-8",
		},
		BodyMatchFunc: func(b []byte) bool {
			return strings.TrimSpace(expect) == string(bytes.TrimSpace(b))
		},
	})
}

func TestHandleDefaultErrorXml(t *testing.T) {

	expect := `<?xml version = "1.0" encoding = "UTF-8"?>
<error>There was a problem proxying the request</error>`
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = "http://localhost:66666"
	})
	ts.Run(t, test.TestCase{
		Path: "/",
		Code: http.StatusInternalServerError,
		Headers: map[string]string{
			header.ContentType: header.TextXML,
		},
		BodyMatchFunc: func(b []byte) bool {
			return strings.TrimSpace(expect) == string(bytes.TrimSpace(b))
		},
	})

	ts.Run(t, test.TestCase{
		Path: "/",
		Code: http.StatusInternalServerError,
		Headers: map[string]string{
			header.ContentType: header.TextXML + "; charset=UTF-8",
		},
		BodyMatchFunc: func(b []byte) bool {
			return strings.TrimSpace(expect) == string(bytes.TrimSpace(b))
		},
	})
}

func TestHandleDefaultErrorJSON(t *testing.T) {

	expect := `
{
    "error": "There was a problem proxying the request"
}
`

	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = "http://localhost:66666"
	})
	ts.Run(t, test.TestCase{
		Path: "/",
		Code: http.StatusInternalServerError,
		Headers: map[string]string{
			header.ContentType: header.ApplicationJSON,
		},
		BodyMatchFunc: func(b []byte) bool {
			return strings.TrimSpace(expect) == string(bytes.TrimSpace(b))
		},
	})

}

// TestHandleErrorJSONEscaping tests that error messages with special characters
// are properly escaped in JSON responses according to RFC 8259
func TestHandleErrorJSONEscaping(t *testing.T) {
	testCases := []struct {
		name        string
		errorMsg    string
		expectedMsg string
	}{
		{
			name:        "single quotes should be unescaped in JSON",
			errorMsg:    "parameter doesn't match the pattern",
			expectedMsg: "parameter doesn't match the pattern",
		},
		{
			name:        "double quotes should be properly handled",
			errorMsg:    `parameter "name" is invalid`,
			expectedMsg: `parameter "name" is invalid`,
		},
		{
			name:        "backslashes should be properly handled",
			errorMsg:    `pattern: \d+\w+`,
			expectedMsg: `pattern: \d+\w+`,
		},
		{
			name:        "newlines should be properly handled",
			errorMsg:    "line1\nline2",
			expectedMsg: "line1\nline2",
		},
		{
			name:        "tabs should be properly handled",
			errorMsg:    "col1\tcol2",
			expectedMsg: "col1\tcol2",
		},
		{
			name:        "complex validation error with regex pattern",
			errorMsg:    `parameter "categoryPurpose" in header has an error: string doesn't match the regular expression "^[a-zA-Z0-9 /\-\?:\(\)\.,'\+]{1,3}$"`,
			expectedMsg: `parameter "categoryPurpose" in header has an error: string doesn't match the regular expression "^[a-zA-Z0-9 /\-\?:\(\)\.,'\+]{1,3}$"`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			// Build a properly initialized API spec
			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.Proxy.ListenPath = "/"
				spec.DoNotTrack = true
			})

			// Get the spec from the gateway
			specs := ts.Gw.apiSpecs
			if len(specs) == 0 {
				t.Fatal("no API specs loaded")
			}
			spec := specs[0]

			// Create error handler
			errorHandler := &ErrorHandler{
				BaseMiddleware: &BaseMiddleware{
					Spec: spec,
					Gw:   ts.Gw,
				},
			}

			// Create a test request with JSON content type
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set(header.ContentType, header.ApplicationJSON)

			// Create response writer
			w := httptest.NewRecorder()

			// Call HandleError with our test error message
			errorHandler.HandleError(w, req, tc.errorMsg, http.StatusBadRequest, true)

			// Get response body
			resp := w.Result()
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("failed to read response body: %v", err)
			}

			// Verify the response is valid JSON
			var jsonResponse map[string]interface{}
			if err := json.Unmarshal(body, &jsonResponse); err != nil {
				t.Fatalf("response is not valid JSON: %v\nBody: %s", err, string(body))
			}

			// Verify the error message is properly escaped
			errorMsg, ok := jsonResponse["error"].(string)
			if !ok {
				t.Fatalf("error field is not a string")
			}

			if errorMsg != tc.expectedMsg {
				t.Errorf("expected error message:\n%s\n\ngot:\n%s", tc.expectedMsg, errorMsg)
			}

			// Verify Content-Type header
			if contentType := resp.Header.Get(header.ContentType); contentType != header.ApplicationJSON {
				t.Errorf("expected Content-Type %s, got %s", header.ApplicationJSON, contentType)
			}
		})
	}
}

// TestHandleErrorXMLNoEscaping verifies that XML responses don't escape special characters
func TestHandleErrorXMLNoEscaping(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Build a properly initialized API spec
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.DoNotTrack = true
	})

	// Get the spec from the gateway
	specs := ts.Gw.apiSpecs
	if len(specs) == 0 {
		t.Fatal("no API specs loaded")
	}
	spec := specs[0]

	// Create error handler
	errorHandler := &ErrorHandler{
		BaseMiddleware: &BaseMiddleware{
			Spec: spec,
			Gw:   ts.Gw,
		},
	}

	// Test error message with special characters
	errorMsg := `parameter "name" doesn't match pattern`

	// Create a test request with XML content type
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set(header.ContentType, header.TextXML)

	// Create response writer
	w := httptest.NewRecorder()

	// Call HandleError
	errorHandler.HandleError(w, req, errorMsg, http.StatusBadRequest, true)

	// Get response body
	resp := w.Result()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	// Verify the error message is NOT escaped (raw content for XML)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, errorMsg) {
		t.Errorf("expected XML body to contain raw error message:\n%s\n\ngot:\n%s", errorMsg, bodyStr)
	}

	// Verify Content-Type header
	if contentType := resp.Header.Get(header.ContentType); contentType != header.TextXML {
		t.Errorf("expected Content-Type %s, got %s", header.TextXML, contentType)
	}
}

package gateway

import (
	"encoding/base64"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	texttemplate "text/template"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/result"
	"github.com/TykTechnologies/tyk/test"
)

func testPrepareTransformNonAscii() (*TransformSpec, string) {
	in := `<?xml version="1.0" encoding="utf-8"?>
<names>
	<name>Jyväskylä</name>
	<name>Hyvinkää</name>
</names>`
	tmpl := `[{{range $x, $s := .names.name}}"{{$s}}"{{if not $x}}, {{end}}{{end}}]`
	tmeta := &TransformSpec{}
	tmeta.TemplateData.Input = apidef.RequestXML
	tmeta.Template = result.Ok(texttemplate.Must(texttemplate.New("blob").Parse(tmpl)))
	return tmeta, in
}

func TestTransformNonAscii(t *testing.T) {
	test.Flaky(t) // TODO: TT-5223

	tmeta, in := testPrepareTransformNonAscii()
	want := `["Jyväskylä", "Hyvinkää"]`

	r := TestReq(t, "GET", "/", in)

	ts := StartTest(nil)
	defer ts.Close()

	ad := &apidef.APIDefinition{}
	spec := &APISpec{APIDefinition: ad}
	base := &BaseMiddleware{Spec: spec, Gw: ts.Gw}

	transform := TransformMiddleware{base}

	if err := transform.transformBody(r, tmeta); err != nil {
		t.Fatalf("wanted nil error, got %v", err)
	}
	gotBs, err := ioutil.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(gotBs); got != want {
		t.Fatalf("wanted body %q, got %q", want, got)
	}
}

func BenchmarkTransformNonAscii(b *testing.B) {
	b.ReportAllocs()

	tmeta, in := testPrepareTransformNonAscii()

	ts := StartTest(nil)
	defer ts.Close()

	ad := &apidef.APIDefinition{}
	spec := &APISpec{APIDefinition: ad}
	base := &BaseMiddleware{Spec: spec, Gw: ts.Gw}

	transform := &TransformMiddleware{base}

	for i := 0; i < b.N; i++ {
		r := TestReq(b, "GET", "/", in)

		if err := transform.transformBody(r, tmeta); err != nil {
			b.Fatalf("wanted nil error, got %v", err)
		}
	}
}

func TestTransformXMLCrash(t *testing.T) {
	// mxj.NewMapXmlReader used to take forever and crash the
	// process by eating up all the memory.
	in := strings.NewReader("not xml")
	r := TestReq(t, "GET", "/", in)
	tmeta := &TransformSpec{}
	tmeta.TemplateData.Input = apidef.RequestXML
	tmeta.Template = result.Ok(texttemplate.Must(apidef.Template.New("").Parse("")))

	ts := StartTest(nil)
	defer ts.Close()

	ad := &apidef.APIDefinition{}
	spec := &APISpec{APIDefinition: ad}
	base := &BaseMiddleware{Spec: spec, Gw: ts.Gw}

	transform := TransformMiddleware{base}

	if err := transform.transformBody(r, tmeta); err == nil {
		t.Fatalf("wanted error, got nil")
	}
}

func testPrepareTransformJSONMarshal(inputType string) (tmeta *TransformSpec, in string) {
	tmeta = &TransformSpec{}
	tmpl := `[{{range $x, $s := .names.name}}{{$s | jsonMarshal}}{{if not $x}}, {{end}}{{end}}]`
	tmeta.TemplateData.Input = apidef.RequestXML
	tmeta.Template = result.Ok(texttemplate.Must(apidef.Template.New("").Parse(tmpl)))

	switch inputType {
	case "json":
		tmeta.TemplateData.Input = apidef.RequestJSON
		in = `{"names": { "name": ["Foo\"oo", "Bàr"] }}`
	case "xml":
		tmeta.TemplateData.Input = apidef.RequestXML
		in = `<names>
	<name>Foo"oo</name>
	<name>Bàr</name>
</names>`
	}

	return tmeta, in
}

func testPrepareTransformXMLMarshal(tmpl string, inputType apidef.RequestInputType) (tmeta *TransformSpec) {
	tmeta = &TransformSpec{}
	tmeta.Template = result.Ok(texttemplate.Must(apidef.Template.New("").Parse(tmpl)))

	switch inputType {
	case apidef.RequestJSON:
		tmeta.TemplateData.Input = apidef.RequestJSON
	case apidef.RequestXML:
		tmeta.TemplateData.Input = apidef.RequestXML
	}

	return tmeta
}

func TestTransformJSONMarshalXMLInput(t *testing.T) {
	tmeta, in := testPrepareTransformJSONMarshal("xml")

	want := `["Foo\"oo", "Bàr"]`
	r := TestReq(t, "GET", "/", in)

	ts := StartTest(nil)
	defer ts.Close()

	ad := &apidef.APIDefinition{}
	spec := &APISpec{APIDefinition: ad}
	base := &BaseMiddleware{Spec: spec, Gw: ts.Gw}

	transform := TransformMiddleware{base}

	if err := transform.transformBody(r, tmeta); err != nil {
		t.Fatalf("wanted nil error, got %v", err)
	}
	gotBs, err := ioutil.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(gotBs); got != want {
		t.Fatalf("wanted body %q, got %q", want, got)
	}
}

func TestTransformJSONMarshalJSONInput(t *testing.T) {
	tmeta, in := testPrepareTransformJSONMarshal("json")

	want := `["Foo\"oo", "Bàr"]`
	r := TestReq(t, "GET", "/", in)

	ts := StartTest(nil)
	defer ts.Close()

	ad := &apidef.APIDefinition{}
	spec := &APISpec{APIDefinition: ad}
	base := &BaseMiddleware{Spec: spec, Gw: ts.Gw}

	transform := TransformMiddleware{base}

	if err := transform.transformBody(r, tmeta); err != nil {
		t.Fatalf("wanted nil error, got %v", err)
	}
	gotBs, err := ioutil.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(gotBs); got != want {
		t.Fatalf("wanted body %q, got %q", want, got)
	}
}

func testPrepareTransformJSONMarshalArray(tb testing.TB) (tmeta *TransformSpec, in string) {
	tmeta = &TransformSpec{}
	tmpl := `[{{ range $key, $value := .array }}{{ if $key }},{{ end }}{{ .abc }}{{ end }}]`
	tmeta.TemplateData.Input = apidef.RequestXML
	tmeta.Template = result.Ok(texttemplate.Must(apidef.Template.New("").Parse(tmpl)))

	tmeta.TemplateData.Input = apidef.RequestJSON
	in = `[{"abc": 123}, {"abc": 456}]`

	return tmeta, in
}

func TestTransformJSONMarshalJSONArrayInput(t *testing.T) {
	tmeta, in := testPrepareTransformJSONMarshalArray(t)

	want := `[123,456]`
	r := TestReq(t, "GET", "/", in)

	ts := StartTest(nil)
	defer ts.Close()

	ad := &apidef.APIDefinition{}
	spec := &APISpec{APIDefinition: ad}
	base := &BaseMiddleware{Spec: spec, Gw: ts.Gw}

	transform := TransformMiddleware{base}

	if err := transform.transformBody(r, tmeta); err != nil {
		t.Fatalf("wanted nil error, got %v", err)
	}
	gotBs, err := ioutil.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(gotBs); got != want {
		t.Fatalf("wanted body %q, got %q", want, got)
	}
}

func BenchmarkTransformJSONMarshal(b *testing.B) {
	b.ReportAllocs()

	tmeta, in := testPrepareTransformJSONMarshal("xml")
	ts := StartTest(nil)
	defer ts.Close()

	ad := &apidef.APIDefinition{}
	spec := &APISpec{APIDefinition: ad}
	base := &BaseMiddleware{Spec: spec, Gw: ts.Gw}

	transform := TransformMiddleware{base}

	for i := 0; i < b.N; i++ {
		r := TestReq(b, "GET", "/", in)
		if err := transform.transformBody(r, tmeta); err != nil {
			b.Fatalf("wanted nil error, got %v", err)
		}
	}
}

func TestTransformXMLMarshal(t *testing.T) {
	assert := func(t *testing.T, input string, tmpl string, output string, inputType apidef.RequestInputType) {
		t.Helper()
		tmeta := testPrepareTransformXMLMarshal(tmpl, inputType)
		r := TestReq(t, "GET", "/", input)

		ts := StartTest(nil)
		defer ts.Close()

		ad := &apidef.APIDefinition{}
		spec := &APISpec{APIDefinition: ad}
		base := &BaseMiddleware{Spec: spec, Gw: ts.Gw}

		transform := TransformMiddleware{base}

		if err := transform.transformBody(r, tmeta); err != nil {
			t.Fatalf("wanted nil error, got %v", err)
		}
		gotBs, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(gotBs); got != output {
			t.Fatalf("wanted body %q, got %q", output, got)
		}
	}

	tmpl := `{{. | xmlMarshal}}`
	output := `<brothers><name>Furkan</name><name>Ahmet</name><name>Mohammad Ali</name></brothers>`
	t.Run("XMLInput", func(t *testing.T) {
		input := `<brothers><name>Furkan</name><name>Ahmet</name><name>Mohammad Ali</name></brothers>`
		assert(t, input, tmpl, output, apidef.RequestXML)
	})

	t.Run("JSONInput", func(t *testing.T) {
		input := `{"brothers": { "name": ["Furkan", "Ahmet", "Mohammad Ali"] }}`
		assert(t, input, tmpl, output, apidef.RequestJSON)
	})

	t.Run("JSONInput with escaped char", func(t *testing.T) {
		input := `{"test":"<"}`
		output = `<test>&lt;</test>`
		assert(t, input, tmpl, output, apidef.RequestJSON)
	})

	t.Run("JSONInput with escaped char, template applied to a single value", func(t *testing.T) {
		input := `{"test":"<"}`
		tmpl = `{{ index . "test" | xmlMarshal }}`
		output = `<string>&lt;</string>`
		assert(t, input, tmpl, output, apidef.RequestJSON)
	})
}

func TestBodyTransformCaseSensitivity(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	assert := func(relativePath string, requestedPath string, bodyMatch string) {
		transformResponseConf := apidef.TemplateMeta{
			Path:   relativePath,
			Method: "GET",
			TemplateData: apidef.TemplateData{
				Mode:           "blob",
				TemplateSource: base64.StdEncoding.EncodeToString([]byte(`{"http_method":"{{.Method}}"}`)),
			},
		}

		responseProcessorConf := []apidef.ResponseProcessor{{Name: "response_body_transform"}}

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.ResponseProcessors = responseProcessorConf
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.ExtendedPaths.TransformResponse = []apidef.TemplateMeta{transformResponseConf}
			})
		})

		ts.Run(t, test.TestCase{
			Path: requestedPath, Code: 200, BodyMatch: bodyMatch,
		})
	}

	// Matches and transforms
	t.Run("Relative path lower, requested path lower", func(t *testing.T) {
		assert("/get", "/get", `{"http_method":"GET"}`)
	})

	// Doesn't match and doesn't transform
	t.Run("Relative path lower, requested path upper", func(t *testing.T) {
		assert("/get", "/Get", `"Method":"GET"`)
	})

	// Doesn't match and doesn't transform
	t.Run("Relative path upper, requested path lower", func(t *testing.T) {
		assert("/Get", "/get", `"Method":"GET"`)
	})

	// Matches and transforms
	t.Run("Relative path upper, requested path upper", func(t *testing.T) {
		assert("/Get", "/Get", `{"http_method":"GET"}`)
	})
}

func TestTransformRequestBody(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	api := BuildAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			v.ExtendedPaths.Transform = []apidef.TemplateMeta{
				{
					Disabled: false,
					Path:     "/get",
					Method:   http.MethodGet,
					TemplateData: apidef.TemplateData{
						Input:          apidef.RequestJSON,
						Mode:           apidef.UseBlob,
						TemplateSource: base64.StdEncoding.EncodeToString([]byte(`{{.engineer | repeat 2}}`)),
					},
				}}
		})
	})[0]

	ts.Gw.LoadAPI(api)

	body := `{"engineer":"Furkan"}`
	bodyMatch := `"Body":"FurkanFurkan"`

	_, _ = ts.Run(t, test.TestCase{Path: "/get", Data: body, BodyMatch: bodyMatch, Code: http.StatusOK})

	t.Run("disabled", func(t *testing.T) {
		UpdateAPIVersion(api, "v1", func(version *apidef.VersionInfo) {
			version.ExtendedPaths.Transform[0].Disabled = true
		})
		ts.Gw.LoadAPI(api)

		_, _ = ts.Run(t, test.TestCase{Path: "/get", Data: body, BodyNotMatch: bodyMatch, Code: http.StatusOK})
	})
}

func TestTransformMiddleware(t *testing.T) {
	t.Run("ProcessRequest", func(t *testing.T) {
		mockEchoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, err := io.Copy(w, r.Body)
			assert.NoError(t, err)
		}))
		t.Cleanup(mockEchoServer.Close)

		ts := StartTest(nil)
		defer ts.Close()

		t.Run("unmatched path passes through with StatusOK", func(t *testing.T) {
			api := BuildAPI(func(spec *APISpec) {
				spec.Proxy.ListenPath = "/"
				UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
					v.ExtendedPaths.Transform = []apidef.TemplateMeta{
						{
							Path:   "/transform",
							Method: http.MethodPost,
							TemplateData: apidef.TemplateData{
								Input:          apidef.RequestJSON,
								Mode:           apidef.UseBlob,
								TemplateSource: base64.StdEncoding.EncodeToString([]byte(`{"hello":"{{.name}}"}`)),
							},
						},
					}
				})
			})[0]
			ts.Gw.LoadAPI(api)

			mw := &TransformMiddleware{
				BaseMiddleware: &BaseMiddleware{
					Spec: api,
					Gw:   ts.Gw,
				},
			}

			req := TestReq(t, http.MethodPost, "/unmatched", `{"name":"world"}`)
			err, code := mw.ProcessRequest(nil, req, nil)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, code)
		})

		t.Run("successful transformation updates request body and returns StatusOK", func(t *testing.T) {
			ts.Gw.BuildAndLoadAPI(
				func(spec *APISpec) {
					spec.Proxy.TargetURL = mockEchoServer.URL
					spec.Proxy.ListenPath = "/"

					UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
						v.ExtendedPaths.Transform = []apidef.TemplateMeta{
							{
								Path:   "/transform",
								Method: http.MethodPost,
								TemplateData: apidef.TemplateData{
									Input:          apidef.RequestJSON,
									Mode:           apidef.UseBlob,
									TemplateSource: base64.StdEncoding.EncodeToString([]byte(`{"greeting":"hello {{.name}}"}`)),
								},
							},
						}
					})
				},
			)

			resp, err := ts.Run(t, test.TestCase{
				Method:    http.MethodPost,
				Path:      "/transform",
				Data:      `{"name":"tyk"}`,
				Code:      http.StatusOK,
				BodyMatch: `{"greeting":"hello tyk"}`,
			})

			assert.NoError(t, err)
			assert.NotNil(t, resp)

			body, err := io.ReadAll(resp.Body)
			assert.NoError(t, err)
			assert.Equal(t, `{"greeting":"hello tyk"}`, string(body))
		})

		t.Run("template compilation error in Result returns StatusInternalServerError", func(t *testing.T) {
			api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.Proxy.ListenPath = "/"
				spec.Proxy.TargetURL = mockEchoServer.URL
				UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
					v.ExtendedPaths.Transform = []apidef.TemplateMeta{
						{
							Path:   "/bad-template",
							Method: http.MethodPost,
							TemplateData: apidef.TemplateData{
								Input:          apidef.RequestJSON,
								Mode:           apidef.UseBlob,
								TemplateSource: base64.StdEncoding.EncodeToString([]byte(`{{ .unclosed`)),
							},
						},
					}
				})
			})[0]

			assert.NotNil(t, api)

			_, _ = ts.Run(t, test.TestCase{
				Method: http.MethodPost,
				Path:   "/bad-template",
				Data:   `{"name":"tyk"}`,
				Code:   http.StatusInternalServerError,
			})
		})

		t.Run("invalid template mode in Result returns StatusInternalServerError", func(t *testing.T) {
			api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.Proxy.ListenPath = "/"
				spec.Proxy.TargetURL = mockEchoServer.URL
				UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
					v.ExtendedPaths.Transform = []apidef.TemplateMeta{
						{
							Path:   "/invalid-mode",
							Method: http.MethodPost,
							TemplateData: apidef.TemplateData{
								Input: apidef.RequestJSON,
								Mode:  "invalid_mode",
							},
						},
					}
				})
			})[0]

			assert.NotNil(t, api)

			_, _ = ts.Run(t, test.TestCase{
				Method: http.MethodPost,
				Path:   "/invalid-mode",
				Data:   `{"name":"tyk"}`,
				Code:   http.StatusInternalServerError,
			})
		})

		t.Run("malformed request body returns StatusInternalServerError", func(t *testing.T) {

			api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.Proxy.ListenPath = "/"
				spec.Proxy.TargetURL = mockEchoServer.URL
				UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
					v.ExtendedPaths.Transform = []apidef.TemplateMeta{
						{
							Path:   "/transform",
							Method: http.MethodPost,
							TemplateData: apidef.TemplateData{
								Input:          apidef.RequestJSON,
								Mode:           apidef.UseBlob,
								TemplateSource: base64.StdEncoding.EncodeToString([]byte(`{"hello":"{{.name}}"}`)),
							},
						},
					}
				})
			})[0]

			assert.NotNil(t, api)

			_, _ = ts.Run(t, test.TestCase{
				Method: http.MethodPost,
				Path:   "/transform",
				Data:   `{malformed-json`,
				Code:   http.StatusInternalServerError,
			})
		})
	})
}

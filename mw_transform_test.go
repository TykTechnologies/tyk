package main

import (
	"io/ioutil"
	"strings"
	"testing"
	"text/template"

	"github.com/TykTechnologies/tyk/apidef"
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
	tmeta.Template = template.Must(template.New("blob").Parse(tmpl))
	return tmeta, in
}

func TestTransformNonAscii(t *testing.T) {
	tmeta, in := testPrepareTransformNonAscii()
	want := `["Jyväskylä", "Hyvinkää"]`

	r := testReq(t, "GET", "/", in)
	if err := transformBody(r, tmeta, false); err != nil {
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
	for i := 0; i < b.N; i++ {
		r := testReq(b, "GET", "/", in)
		if err := transformBody(r, tmeta, false); err != nil {
			b.Fatalf("wanted nil error, got %v", err)
		}
	}
}

func TestTransformXMLCrash(t *testing.T) {
	// mxj.NewMapXmlReader used to take forever and crash the
	// process by eating up all the memory.
	in := strings.NewReader("not xml")
	r := testReq(t, "GET", "/", in)
	tmeta := &TransformSpec{}
	tmeta.TemplateData.Input = apidef.RequestXML
	tmeta.Template = template.Must(apidef.Template.New("").Parse(""))
	if err := transformBody(r, tmeta, false); err == nil {
		t.Fatalf("wanted error, got nil")
	}
}

func testPrepareTransformJSONMarshal(inputType string) (tmeta *TransformSpec, in string) {
	tmeta = &TransformSpec{}
	tmpl := `[{{range $x, $s := .names.name}}{{$s | jsonMarshal}}{{if not $x}}, {{end}}{{end}}]`
	tmeta.TemplateData.Input = apidef.RequestXML
	tmeta.Template = template.Must(apidef.Template.New("").Parse(tmpl))

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
	tmeta.Template = template.Must(apidef.Template.New("").Parse(tmpl))

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
	r := testReq(t, "GET", "/", in)
	if err := transformBody(r, tmeta, false); err != nil {
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
	r := testReq(t, "GET", "/", in)
	if err := transformBody(r, tmeta, false); err != nil {
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
	tmeta.Template = template.Must(apidef.Template.New("").Parse(tmpl))

	tmeta.TemplateData.Input = apidef.RequestJSON
	in = `[{"abc": 123}, {"abc": 456}]`

	return tmeta, in
}

func TestTransformJSONMarshalJSONArrayInput(t *testing.T) {
	tmeta, in := testPrepareTransformJSONMarshalArray(t)

	want := `[123,456]`
	r := testReq(t, "GET", "/", in)
	if err := transformBody(r, tmeta, false); err != nil {
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

	for i := 0; i < b.N; i++ {
		r := testReq(b, "GET", "/", in)
		if err := transformBody(r, tmeta, false); err != nil {
			b.Fatalf("wanted nil error, got %v", err)
		}
	}
}

func TestTransformXMLMarshal(t *testing.T) {
	assert := func(t *testing.T, input string, tmpl string, output string, inputType apidef.RequestInputType) {
		tmeta := testPrepareTransformXMLMarshal(tmpl, inputType)
		r := testReq(t, "GET", "/", input)
		if err := transformBody(r, tmeta, false); err != nil {
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

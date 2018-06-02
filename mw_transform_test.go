package main

import (
	"io/ioutil"
	"strings"
	"testing"
	"text/template"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestTransformNonAscii(t *testing.T) {
	in := `<?xml version="1.0" encoding="utf-8"?>
<names>
	<name>Jyväskylä</name>
	<name>Hyvinkää</name>
</names>`
	want := `["Jyväskylä", "Hyvinkää"]`
	tmpl := `[{{range $x, $s := .names.name}}"{{$s}}"{{if not $x}}, {{end}}{{end}}]`
	r := testReq(t, "GET", "/", in)
	tmeta := &TransformSpec{}
	tmeta.TemplateData.Input = apidef.RequestXML
	tmeta.Template = template.Must(template.New("blob").Parse(tmpl))
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

func TestTransformXMLCrash(t *testing.T) {
	// mxj.NewMapXmlReader used to take forever and crash the
	// process by eating up all the memory.
	in := strings.NewReader("not xml")
	r := testReq(t, "GET", "/", in)
	tmeta := &TransformSpec{}
	tmeta.TemplateData.Input = apidef.RequestXML
	tmeta.Template = template.Must(apiTemplate.New("").Parse(""))
	if err := transformBody(r, tmeta, false); err == nil {
		t.Fatalf("wanted error, got nil")
	}
}

func testPrepareTransformJSONMarshal(tb testing.TB, inputType string) (tmeta *TransformSpec, in string) {
	tmeta = &TransformSpec{}
	tmpl := `[{{range $x, $s := .names.name}}{{$s | jsonMarshal}}{{if not $x}}, {{end}}{{end}}]`
	tmeta.TemplateData.Input = apidef.RequestXML
	tmeta.Template = template.Must(apiTemplate.New("").Parse(tmpl))

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

func TestTransformJSONMarshalXMLInput(t *testing.T) {
	tmeta, in := testPrepareTransformJSONMarshal(t, "xml")

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
	tmeta, in := testPrepareTransformJSONMarshal(t, "json")

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


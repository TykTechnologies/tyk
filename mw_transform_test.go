package main

import (
	"io/ioutil"
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

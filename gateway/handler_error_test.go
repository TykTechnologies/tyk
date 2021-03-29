package gateway

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/headers"
	"github.com/TykTechnologies/tyk/test"
)

func TestHandleError_text_xml(t *testing.T) {
	file := filepath.Join(config.Global().TemplatePath, "error_500.xml")
	xml := `<error>
	<code>500</code>
	<message>{{.Message}}</message>
</error>`
	err := ioutil.WriteFile(file, []byte(xml), 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file)
	expect := `
<error>
	<code>500</code>
	<message>There was a problem proxying the request</message>
</error>`
	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = "http://localhost:66666"
	})
	ts.Run(t, test.TestCase{
		Path: "/",
		Code: http.StatusInternalServerError,
		Headers: map[string]string{
			headers.ContentType: headers.TextXML,
		},
		BodyMatchFunc: func(b []byte) bool {
			return strings.TrimSpace(expect) == string(bytes.TrimSpace(b))
		},
	})

	ts.Run(t, test.TestCase{
		Path: "/",
		Code: http.StatusInternalServerError,
		Headers: map[string]string{
			headers.ContentType: headers.TextXML + "; charset=UTF-8",
		},
		BodyMatchFunc: func(b []byte) bool {
			return strings.TrimSpace(expect) == string(bytes.TrimSpace(b))
		},
	})
}

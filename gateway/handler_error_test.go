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

func BenchmarkErrorLogTransaction(b *testing.B) {
	b.Run("AccessLogs enabled with Hashkeys set to true", func(b *testing.B) {
		conf := func(globalConf *config.Config) {
			globalConf.HashKeys = true
			globalConf.AccessLogs.Enabled = true
		}
		benchmarkErrorLogTransaction(b, conf)

	})
	b.Run("AccessLogs enabled with Hashkeys set to false", func(b *testing.B) {
		conf := func(globalConf *config.Config) {
			globalConf.HashKeys = false
			globalConf.AccessLogs.Enabled = true
		}
		benchmarkErrorLogTransaction(b, conf)
	})

	b.Run("AccessLogs disabled with Hashkeys set to true", func(b *testing.B) {
		conf := func(globalConf *config.Config) {
			globalConf.HashKeys = true
			globalConf.AccessLogs.Enabled = false
		}
		benchmarkErrorLogTransaction(b, conf)
	})

	b.Run("AccessLogs disabled with Hashkeys set to false", func(b *testing.B) {
		conf := func(globalConf *config.Config) {
			globalConf.HashKeys = false
			globalConf.AccessLogs.Enabled = false
		}
		benchmarkErrorLogTransaction(b, conf)
	})
}

func benchmarkErrorLogTransaction(b *testing.B, conf func(globalConf *config.Config)) {
	b.ReportAllocs()
	b.Helper()
	b.ResetTimer()

	ts := StartTest(conf)
	defer ts.Close()

	for i := 0; i < b.N; i++ {
		ts.Run(b, test.TestCase{
			Code: http.StatusNotFound,
		})
	}
}

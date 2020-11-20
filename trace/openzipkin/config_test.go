package openzipkin

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/TykTechnologies/tyk/config"
)

func TestLoad(t *testing.T) {
	dir, err := ioutil.TempDir("", "tyk")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	f := filepath.Join(dir, "zipkin.json")
	err = ioutil.WriteFile(f, []byte(`{
			"tracing": {
			  "enabled": true,
			  "name": "zipkin",
			  "options": {
				"reporter": {
				  "url": "http:localhost:9411/api/v2/spans"
				}
			  }
			}
		  }
		  `), 0600)
	if err != nil {
		t.Fatal(err)
	}
	var c config.Config
	err = config.Load([]string{f}, &c)
	if err != nil {
		t.Fatal(err)
	}
	z, err := Load(c.Tracer.Options)
	if err != nil {
		t.Fatal(err)
	}
	u := "http:localhost:9411/api/v2/spans"
	if z.Reporter.URL != u {
		t.Errorf("expected %q got %q", u, z.Reporter.URL)
	}

}

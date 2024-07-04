package openzipkin

import (
	"testing"

	"github.com/TykTechnologies/tyk/config"
)

func TestLoad(t *testing.T) {
	f := "testdata/zipkin.json"
	var c config.Config
	err := config.Load([]string{f}, &c)
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

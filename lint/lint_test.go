package lint

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/config"
)

func TestMain(m *testing.M) {
	// Use the root package, as that's where the directories and
	// files required to run the gateway are.
	os.Chdir("..")
	os.Exit(m.Run())
}

func defaultConf() *config.Config {
	var conf config.Config
	config.WriteDefault("", &conf)
	return &conf
}

var tests = []struct {
	name    string
	changes func(*config.Config)
	want    []string
}{
	{"Default", func(*config.Config) {}, nil},
	{
		"ListenAddrWithPort",
		func(c *config.Config) { c.ListenAddress = "localhost:8080" },
		[]string{`listen port should be set in listen_port`},
	},
	{
		"NotExistTemplatePath",
		func(c *config.Config) { c.TemplatePath = "missing" },
		[]string{`template_path "missing" does not exist`},
	},
	{
		"NotExistTykJSPath",
		func(c *config.Config) { c.TykJSPath = "missing" },
		[]string{`tyk_js_path "missing" does not exist`},
	},
	{
		"NotExistMiddlewarePath",
		func(c *config.Config) { c.MiddlewarePath = "missing" },
		[]string{`middleware_path "missing" does not exist`},
	},
	{
		"NotExistAppPath",
		func(c *config.Config) { c.AppPath = "missing" },
		[]string{`app_path "missing" does not exist`},
	},
}

func TestWarnings(t *testing.T) {
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conf := defaultConf()
			tc.changes(conf)
			got := allWarnings(conf)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("want:\n%s\ngot:\n%s",
					strings.Join(tc.want, "\n"),
					strings.Join(got, "\n"))
			}
		})
	}
}

package lint

import (
	"reflect"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/config"
)

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

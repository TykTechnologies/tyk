package lint

import (
	"encoding/json"
	"io/ioutil"
	"os"
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

// onDefaults overlays src as a JSON string on top of the default config
// as a JSON. This can be useful to change the default config in ways
// that would not be possible via the config.Config struct, such as
// using invalid types or adding extra fields.
func onDefaults(src string) string {
	conf := map[string]interface{}{}
	defBytes, _ := json.Marshal(config.Default)
	json.Unmarshal(defBytes, &conf)
	json.Unmarshal([]byte(src), &conf)
	resBytes, _ := json.Marshal(conf)
	return string(resBytes)
}

var tests = []struct {
	name string
	in   string
	want interface{}
}{
	{
		"InvalidJSON", `{`,
		"unexpected EOF",
	},
	{
		"WrongType", `{"enable_jsvm": 3}`,
		"cannot unmarshal number into Go struct field Config.enable_jsvm of type bool",
	},
	{
		"FieldTypo", `{"enable_jsvmm": true}`,
		"Additional property enable_jsvmm is not allowed",
	},
	{"Empty", `{}`, nil},
	{"Default", onDefaults(`{}`), nil},
	{"OldMonitor", `{"Monitor": {}}`, nil},
	{"NullObject", `{"event_handlers": null}`, nil},
}

func allContains(got, want []string) bool {
	if len(want) != len(got) {
		return false
	}
	for i := range want {
		if !strings.Contains(got[i], want[i]) {
			return false
		}
	}
	return true
}

func TestLint(t *testing.T) {
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := ioutil.TempFile("", "tyk-lint")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteString(tc.in); err != nil {
				t.Fatal(err)
			}
			f.Close()
			_, got, err := Run([]string{f.Name()})
			if err != nil {
				got = []string{err.Error()}
			}
			want := []string{}
			switch x := tc.want.(type) {
			case nil:
			case string:
				want = []string{x}
			case []string:
				want = x
			default:
				t.Fatalf("unexpected want type: %T\n", x)
			}
			if !allContains(got, want) {
				t.Fatalf("want:\n%s\ngot:\n%s",
					strings.Join(want, "\n"),
					strings.Join(got, "\n"))
			}
		})
	}
}

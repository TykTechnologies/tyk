package linter

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/v3/config"
)

func TestMain(m *testing.M) {
	// Use the root package, as that's where the directories and
	// files required to run the gateway are.
	os.Chdir("../..")
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
	{
		"MissingPath", `{"app_path": "missing-path"}`,
		"app_path: Path does not exist or is not accessible",
	},
	{
		"ExtraPort", `{"listen_address": "foo.com:8080"}`,
		"listen_address: Address should be a host without port",
	},
	{
		"BadHost", `{"storage": {"host": "::::"}}`,
		"storage.host: Address should be a host without port",
	},
	{
		"BadLogLevel", `{"log_level": "catastrophic"}`,
		`log_level: log_level must be one of the following: "", "debug", "info", "warn", "error"`,
	},
	{
		"BadStorageType", `{"storage": {"type": "cd-rom"}}`,
		`storage.type: storage.type must be one of the following: "", "redis"`,
	},
	{
		"BadPolicySource", `{"policies": {"policy_source": "internet"}}`,
		`policies.policy_source: policies.policy_source must be one of the following: "", "service", "rpc"`,
	},
	{
		"MalformedDnsCacheEntry", `{"dns_cache": { "enabled": true, "tttl": 10} }`,
		`tttl: Additional property tttl is not allowed`,
	},
	{
		"BadDnsCacheTTL", `{"dns_cache": { "enabled": false, "ttl": -2 } }`,
		`dns_cache.ttl: Must be greater than or equal to -1`,
	},
	{
		"ExtraDnsCacheCheckInterval", `{"dns_cache": { "enabled": true, "ttl": -1, "check_interval": 2500 } }`,
		`check_interval: Additional property check_interval is not allowed`,
	},
	{
		"InvalidDnsCacheMultipleIPsHandleStrategy", `{"dns_cache": { "enabled": true, "ttl": 1, "multiple_ips_handle_strategy": "true" } }`,
		`dns_cache.multiple_ips_handle_strategy: dns_cache.multiple_ips_handle_strategy must be one of the following: "pick_first", "random", "no_cache"`,
	},
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

			confSchema, err := ioutil.ReadFile("cli/linter/schema.json")
			if err != nil {
				t.Fatal(err)
			}

			_, got, err := Run(string(confSchema), []string{f.Name()})
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

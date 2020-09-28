package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/v3/apidef"
)

func TestDefaultValueAndWriteDefaultConf(t *testing.T) {
	cases := []struct {
		FieldName   string
		EnvVarName  string
		FieldGetter func(*Config) interface{}

		defaultValue  interface{}
		expectedValue interface{}
	}{
		{
			"ListenPort", "TYK_GW_LISTENPORT",
			func(c *Config) interface{} { return c.ListenPort },
			8080, 9090,
		},
		{
			"DnsCacheEnabled", "TYK_GW_DNSCACHE_ENABLED",
			func(c *Config) interface{} { return c.DnsCache.Enabled },
			false, true,
		},
		{
			"DnsCacheTTL", "TYK_GW_DNSCACHE_TTL",
			func(c *Config) interface{} { return c.DnsCache.TTL },
			int64(3600), int64(300),
		},
		{
			"CheckInterval", "TYK_GW_DNSCACHE_CHECKINTERVAL",
			func(c *Config) interface{} { return c.DnsCache.CheckInterval },
			int64(60),
			int64(60), //CheckInterval shouldn't be configured from *.conf and env var
		},
		{
			"CheckMultipleIPsHandleStrategy", "TYK_GW_DNSCACHE_MULTIPLEIPSHANDLESTRATEGY",
			func(c *Config) interface{} { return c.DnsCache.MultipleIPsHandleStrategy },
			NoCacheStrategy,
			RandomStrategy,
		},
	}

	for _, tc := range cases {
		t.Run(tc.FieldName, func(t *testing.T) {
			conf := &Config{}
			os.Unsetenv(tc.EnvVarName)
			defer os.Unsetenv(tc.EnvVarName)
			if err := WriteDefault("", conf); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(tc.FieldGetter(conf), tc.defaultValue) {
				t.Fatalf("Expected %v to be set to its default %v, but got %v", tc.FieldName, tc.defaultValue, tc.FieldGetter(conf))
			}
			expectedValue := fmt.Sprint(tc.expectedValue)
			os.Setenv(tc.EnvVarName, expectedValue)
			if err := WriteDefault("", conf); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(tc.FieldGetter(conf), tc.expectedValue) {
				t.Fatalf("Expected %s to be set to %v, but got %v", tc.FieldName, tc.expectedValue, tc.FieldGetter(conf))
			}
		})
	}
}

func TestConfigFiles(t *testing.T) {
	dir, err := ioutil.TempDir("", "tyk")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	conf := &Config{}
	path1 := filepath.Join(dir, "tyk1.conf")
	path2 := filepath.Join(dir, "tyk2.conf")

	if err := WriteDefault(path1, conf); err != nil {
		t.Fatal(err)
	}
	if conf.ListenPort != 8080 {
		t.Fatalf("Expected ListenPort to be set to its default")
	}
	bs, _ := ioutil.ReadFile(path1)
	if !strings.Contains(string(bs), "8080") {
		t.Fatalf("Expected 8080 to be in the written conf file")
	}
	os.Remove(path1)

	paths := []string{path1, path2}
	// should write default config to path1 and return nil
	if err := Load(paths, conf); err != nil {
		t.Fatalf("Load with no existing configs errored")
	}
	if _, err := os.Stat(path1); err != nil {
		t.Fatalf("Load with no configs did not write a default config file")
	}
	if _, err := os.Stat(path2); err == nil {
		t.Fatalf("Load with no configs wrote too many default config files")
	}
	if conf.OriginalPath != path1 {
		t.Fatalf("OriginalPath was not set properly")
	}

	// both exist, we use path1
	os.Link(path1, path2)
	if err := Load(paths, conf); err != nil {
		t.Fatalf("Load with an existing config errored")
	}
	if conf.OriginalPath != path1 {
		t.Fatalf("OriginalPath was not set properly")
	}

	// path2 exists but path1 doesn't
	os.Remove(path1)
	if err := Load(paths, conf); err != nil {
		t.Fatalf("Load with an existing config errored")
	}
	if _, err := os.Stat(path1); err == nil {
		t.Fatalf("Load with a config wrote a default config file")
	}
	if conf.OriginalPath != path2 {
		t.Fatalf("OriginalPath was not set properly")
	}

	// path1 exists but is invalid
	os.Remove(path2)
	ioutil.WriteFile(path1, []byte("{"), 0644)
	if err := Load(paths, conf); err == nil {
		t.Fatalf("Load with an invalid config did not error")
	}
}

func TestConfig_GetEventTriggers(t *testing.T) {

	assert := func(t *testing.T, config string, expected string) {
		conf := &Config{}

		f, err := ioutil.TempFile("", "tyk.conf")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()

		_, err = f.Write([]byte(config))
		if err != nil {
			t.Fatal(err)
		}

		paths := []string{f.Name()}

		if err := Load(paths, conf); err != nil {
			t.Fatal(err)
		}

		triggers := conf.GetEventTriggers()

		if _, ok := triggers[apidef.TykEvent(expected)]; !ok || len(triggers) != 1 {
			t.Fatal("Config is not loaded correctly")
		}
	}

	t.Run("Deprecated configuration", func(t *testing.T) {
		deprecated := `{"event_trigers_defunct": {"deprecated": []}}`
		assert(t, deprecated, "deprecated")
	})

	t.Run("Current configuration", func(t *testing.T) {
		current := `{"event_triggers_defunct": {"current": []}}`
		assert(t, current, "current")
	})

	t.Run("Both configured", func(t *testing.T) {
		both := `{"event_trigers_defunct": {"deprecated": []}, "event_triggers_defunct": {"current": []}}`
		assert(t, both, "current")
	})

}

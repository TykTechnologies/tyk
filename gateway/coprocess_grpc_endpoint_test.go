package gateway

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/config"
)

// TestBareGRPCEndpoint covers every form coprocess_grpc_server is documented or
// observed to take. `dns:///host:port` matters most: it is what the round-robin
// option's own documentation tells operators to write, and it is the form where
// the endpoint is in the URL's path rather than its host.
func TestBareGRPCEndpoint(t *testing.T) {
	cases := []struct {
		raw     string
		want    string
		wantOK  bool
		comment string
	}{
		{"tcp://plugin:9001", "plugin:9001", true, "the default form"},
		{"plugin:9001", "plugin:9001", true, "no scheme"},
		{"dns:///plugin:9001", "plugin:9001", true, "what the round-robin docs prescribe"},
		{"dns://8.8.8.8/plugin:9001", "plugin:9001", true, "explicit DNS authority"},
		{"dns:plugin:9001", "plugin:9001", true, "short dns form"},
		{"tcp://10.0.0.1:9001", "10.0.0.1:9001", true, "IP literal"},
		{" tcp://plugin:9001 ", "plugin:9001", true, "surrounding whitespace"},
		{"unix:///var/run/plugin.sock", "", false, "not host:port — leave the stock resolver alone"},
		{"plugin", "", false, "no port"},
		{"", "", false, "empty"},
	}

	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			got, ok := bareGRPCEndpoint(tc.raw)
			if ok != tc.wantOK || got != tc.want {
				t.Errorf("bareGRPCEndpoint(%q) = (%q, %v), want (%q, %v) — %s",
					tc.raw, got, ok, tc.want, tc.wantOK, tc.comment)
			}
		})
	}
}

// TestGRPCDNSDiscoveryEnvVars pins the environment variable names down. Config
// keys are derived by uppercasing the field path with no word splitting, and
// refresh_interval has to parse as a duration string from the environment as
// it does from JSON.
func TestGRPCDNSDiscoveryEnvVars(t *testing.T) {
	t.Setenv("TYK_GW_COPROCESSOPTIONS_GRPCDNSDISCOVERY_ENABLED", "true")
	t.Setenv("TYK_GW_COPROCESSOPTIONS_GRPCDNSDISCOVERY_REFRESHINTERVAL", "15s")

	conf := config.Config{}
	if err := config.Load([]string{filepath.Join(t.TempDir(), "absent.conf")}, &conf); err != nil {
		t.Fatalf("load config: %v", err)
	}

	got := conf.CoProcessOptions.GRPCDNSDiscovery
	if !got.Enabled {
		t.Error("TYK_GW_COPROCESSOPTIONS_GRPCDNSDISCOVERY_ENABLED did not apply")
	}
	if time.Duration(got.RefreshInterval) != 15*time.Second {
		t.Errorf("TYK_GW_COPROCESSOPTIONS_GRPCDNSDISCOVERY_REFRESHINTERVAL did not apply: got %v, want 15s",
			time.Duration(got.RefreshInterval))
	}
}

func TestGRPCDNSDiscoveryConfigJSON(t *testing.T) {
	var conf config.CoProcessConfig
	raw := `{"grpc_dns_discovery": {"enabled": true, "refresh_interval": "10s"}}`
	if err := json.Unmarshal([]byte(raw), &conf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !conf.GRPCDNSDiscovery.Enabled || time.Duration(conf.GRPCDNSDiscovery.RefreshInterval) != 10*time.Second {
		t.Errorf("got %+v, want enabled with 10s", conf.GRPCDNSDiscovery)
	}
}

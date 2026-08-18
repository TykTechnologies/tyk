package gateway

import (
	"path/filepath"
	"testing"

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

// TestDNSRefreshIntervalEnvVar pins the environment variable name down.
//
// It is worth a test because it is not what anyone writes by hand. Config keys
// are derived by uppercasing the field path with no word splitting, so it is
// TYK_GW_COPROCESSOPTIONS_GRPCDNSREFRESHINTERVAL and not
// ..._GRPC_DNS_REFRESH_INTERVAL. Adding an envconfig tag to force the
// underscored form is not a fix: a tag value also registers as an unprefixed
// alias, so a bare GRPC_DNS_REFRESH_INTERVAL in the environment would silently
// configure the gateway.
//
// Only the plugin path has an environment variable, and only the plugin path
// should: coprocess_grpc_server is one gateway-level target shared by every API
// with a gRPC plugin. The upstream equivalent is per-API
// (proxy.dns_load_balancing), because which upstream to rediscover is a
// property of one API rather than of the gateway.
func TestDNSRefreshIntervalEnvVar(t *testing.T) {
	t.Setenv("TYK_GW_COPROCESSOPTIONS_GRPCDNSREFRESHINTERVAL", "15")

	// Load from a config file that does not exist, so only defaults and the
	// environment are in play.
	conf := config.Config{}
	if err := config.Load([]string{filepath.Join(t.TempDir(), "absent.conf")}, &conf); err != nil {
		t.Fatalf("load config: %v", err)
	}

	if got := conf.CoProcessOptions.GRPCDNSRefreshInterval; got != 15 {
		t.Errorf("TYK_GW_COPROCESSOPTIONS_GRPCDNSREFRESHINTERVAL did not apply: got %d, want 15", got)
	}
}

// TestResolveDNSRefreshInterval covers the sentinel and the floor. 0 cannot
// mean "disabled" because defaults are applied as `if conf.X == 0 { ... }`, so
// a negative value carries that meaning, as dns_cache.ttl already does.
func TestResolveDNSRefreshInterval(t *testing.T) {
	cases := []struct {
		seconds     int64
		wantSeconds float64
		wantEnabled bool
	}{
		{0, 30, true},   // unset -> default
		{-1, 0, false},  // sentinel -> off
		{-30, 0, false}, // any negative -> off
		{1, 10, true},   // below the floor -> floor
		{10, 10, true},  // the floor itself
		{45, 45, true},  // above the floor -> as configured
	}

	for _, tc := range cases {
		interval, enabled := config.ResolveDNSRefreshInterval(tc.seconds)
		if enabled != tc.wantEnabled || interval.Seconds() != tc.wantSeconds {
			t.Errorf("ResolveDNSRefreshInterval(%d) = (%v, %v), want (%vs, %v)",
				tc.seconds, interval, enabled, tc.wantSeconds, tc.wantEnabled)
		}
	}
}

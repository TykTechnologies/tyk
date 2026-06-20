package plugin

import (
	"strings"
	"testing"

	kingpin "github.com/alecthomas/kingpin/v2"
)

// Verifies: STK-REQ-047, SYS-REQ-135, SW-REQ-122
// STK-REQ-047:STK-REQ-047-AC-03:acceptance
// SYS-REQ-135:nominal:nominal
// SW-REQ-122:nominal:nominal
// SW-REQ-122:error_handling:nominal
// SW-REQ-122:error_handling:negative
func TestCLICommandSurfaceReqProof_PluginLoaderAndRegistration(t *testing.T) {
	missingFile := "missing-plugin.so"
	symbol := "TestSymbol"

	cases := []struct {
		name string
		run  func() error
		want string
	}{
		{
			name: "missing plugin returns explicit load error",
			run: func() error {
				return (&pluginLoader{file: &missingFile, symbol: &symbol}).load()
			},
			want: "unexpected error",
		},
		{
			name: "load wrapper converts panic to error",
			run: func() error {
				return (&pluginLoader{}).Load(nil)
			},
			want: "unexpected panic",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}

	(&pluginLoader{}).info("ignored")

	app := kingpin.New("test", "test")
	AddTo(app)
	pluginCmd := findCommand(app.Model().Commands, "plugin")
	if pluginCmd == nil {
		t.Fatal("plugin command was not registered")
	}
	loadCmd := findCommand(pluginCmd.Commands, "load")
	if loadCmd == nil {
		t.Fatal("plugin load subcommand was not registered")
	}
	for _, name := range []string{"file", "symbol"} {
		if findFlag(loadCmd.Flags, name) == nil {
			t.Fatalf("plugin load flag %q was not registered", name)
		}
	}
}

// Verifies: SW-REQ-122
func findCommand(commands []*kingpin.CmdModel, name string) *kingpin.CmdModel {
	for _, cmd := range commands {
		if cmd.Name == name {
			return cmd
		}
	}
	return nil
}

// Verifies: SW-REQ-122
func findFlag(flags []*kingpin.FlagModel, name string) *kingpin.FlagModel {
	for _, flag := range flags {
		if flag.Name == name {
			return flag
		}
	}
	return nil
}

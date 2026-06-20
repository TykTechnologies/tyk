package cli

import (
	"os"
	"sync"
	"testing"

	kingpin "github.com/alecthomas/kingpin/v2"
)

// Verifies: STK-REQ-047, SYS-REQ-135, SW-REQ-122
// STK-REQ-047:STK-REQ-047-AC-01:acceptance
// STK-REQ-047:STK-REQ-047-AC-02:acceptance
// SYS-REQ-135:nominal:nominal
// SW-REQ-122:nominal:nominal
// SW-REQ-122:boundary:nominal
// MCDC SYS-REQ-135: cli_command_surface_operation_requested=T, cli_command_surface_result_determined=T => TRUE
func TestCLICommandSurfaceReqProof_InitSetupAndParse(t *testing.T) {
	resetCLIForReqProofTest()
	t.Cleanup(resetCLIForReqProofTest)

	Init([]string{"tyk.conf"})
	firstApp := app
	Init([]string{"ignored.conf"})
	if app != firstApp {
		t.Fatal("Init must only configure the global command application once")
	}

	for _, name := range []string{"start", "lint", "version", "import", "bundle", "plugin"} {
		if findCommand(app.Model().Commands, name) == nil {
			t.Fatalf("expected top-level command %q to be registered", name)
		}
	}

	start := findCommand(app.Model().Commands, "start")
	for _, name := range []string{"conf", "port", "memprofile", "cpuprofile", "blockprofile", "mutexprofile", "httpprofile", "debug", "log-instrumentation"} {
		if findFlag(start.Flags, name) == nil {
			t.Fatalf("expected start flag %q to be registered", name)
		}
	}

	if selected, err := app.Parse([]string{"start", "--conf", "custom.conf", "--port", "8181", "--debug"}); err != nil {
		t.Fatalf("parse start command: %v", err)
	} else if selected != "start" {
		t.Fatalf("parse selected %q, want start", selected)
	}
	if *Conf != "custom.conf" || *Port != "8181" || !*DebugMode || !DefaultMode {
		t.Fatalf("start parse did not bind expected globals: conf=%q port=%q debug=%v default=%v", *Conf, *Port, *DebugMode, DefaultMode)
	}

	resetCLIForReqProofTest()
	setup([]string{"tyk.conf"})
	previousArgs := os.Args
	t.Cleanup(func() { os.Args = previousArgs })
	os.Args = []string{"tyk", "start", "--conf", "parsed.conf"}
	Parse()
	if *Conf != "parsed.conf" || !DefaultMode {
		t.Fatalf("Parse did not dispatch through the configured application: conf=%q default=%v", *Conf, DefaultMode)
	}
}

// Verifies: SW-REQ-122
func resetCLIForReqProofTest() {
	Conf = nil
	Port = nil
	MemProfile = nil
	CPUProfile = nil
	BlockProfile = nil
	MutexProfile = nil
	HTTPProfile = nil
	DebugMode = nil
	LogInstrumentation = nil
	DefaultMode = false
	app = nil
	initOnce = sync.Once{}
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

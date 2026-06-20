package version

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	kingpin "github.com/alecthomas/kingpin/v2"
)

// Verifies: STK-REQ-047, SYS-REQ-135, SW-REQ-122
// STK-REQ-047:STK-REQ-047-AC-04:acceptance
// SYS-REQ-135:nominal:nominal
// SW-REQ-122:nominal:nominal
// SW-REQ-122:boundary:nominal
func TestCLICommandSurfaceReqProof_VersionOutputAndRegistration(t *testing.T) {
	asJSON := false
	info := &versionInfo{
		Version:   "1.2.3",
		BuiltBy:   "tester",
		BuildDate: "2026-06-20",
		Commit:    "abc123",
		Go: runtimeInfo{
			Os:      "linux",
			Arch:    "amd64",
			Version: "go1.99",
		},
		asJson: &asJSON,
	}

	for _, want := range []string{
		"Release version: 1.2.3",
		"Built by:        tester",
		"Build date:      2026-06-20",
		"Commit:          abc123",
		"Go version:      go1.99",
		"OS/Arch:         linux/amd64",
	} {
		if got := info.String(); !strings.Contains(got, want) {
			t.Fatalf("String() = %q, want substring %q", got, want)
		}
	}

	textOutput := captureStdout(t, func() {
		if err := info.Run(nil); err != nil {
			t.Fatalf("Run text output: %v", err)
		}
	})
	if !strings.Contains(textOutput, "Release version: 1.2.3") {
		t.Fatalf("text output = %q", textOutput)
	}

	asJSON = true
	jsonOutput := captureStdout(t, func() {
		if err := info.Run(nil); err != nil {
			t.Fatalf("Run JSON output: %v", err)
		}
	})
	var decoded versionInfo
	if err := json.Unmarshal([]byte(jsonOutput), &decoded); err != nil {
		t.Fatalf("version JSON did not decode: %v", err)
	}
	if decoded.Version != info.Version || decoded.Go.Arch != info.Go.Arch {
		t.Fatalf("decoded version = %+v, want %+v", decoded, info)
	}

	app := kingpin.New("test", "test")
	AddTo(app)
	versionCmd := findCommand(app.Model().Commands, "version")
	if versionCmd == nil {
		t.Fatal("version command was not registered")
	}
	if findFlag(versionCmd.Flags, "json") == nil {
		t.Fatal("version json flag was not registered")
	}
}

// Verifies: SW-REQ-122
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	previous := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("open stdout pipe: %v", err)
	}
	os.Stdout = writer
	t.Cleanup(func() { os.Stdout = previous })

	fn()

	if err := writer.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	os.Stdout = previous
	return string(out)
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

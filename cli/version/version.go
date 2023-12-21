package version

//lint:file-ignore faillint This file should be ignored by faillint (fmt in use).

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"

	kingpin "github.com/alecthomas/kingpin/v2"

	"github.com/TykTechnologies/tyk/internal/build"
)

const (
	cmdName = "version"
	cmdDesc = "Version and build information"
)

type versionInfo struct {
	Version   string
	BuiltBy   string
	BuildDate string
	Commit    string

	// Go contains build related information
	Go runtimeInfo

	// Flags, unexposed
	asJson *bool
}

type runtimeInfo struct {
	Os      string
	Arch    string
	Version string
}

// String implements fmt.Stringer for the version info.
func (v *versionInfo) String() string {
	var output strings.Builder
	output.WriteString("Release version: " + v.Version + "\n")
	output.WriteString("Built by:        " + v.BuiltBy + "\n")
	output.WriteString("Build date:      " + v.BuildDate + "\n")
	output.WriteString("Commit:          " + v.Commit + "\n")
	output.WriteString("Go version:      " + v.Go.Version + "\n")
	output.WriteString("OS/Arch:         " + v.Go.Os + "/" + v.Go.Arch + "\n")
	return output.String()
}

// Run is the entry point for printing out version information.
func (v *versionInfo) Run(ctx *kingpin.ParseContext) (err error) {
	if *v.asJson {
		out, err := json.MarshalIndent(v, "", "    ")
		if err != nil {
			return err
		}

		fmt.Println(string(out))
		return nil
	}

	fmt.Println(v)
	return nil
}

// AddTo initializes a version info object.
func AddTo(app *kingpin.Application) {
	cmd := app.Command(cmdName, cmdDesc)

	info := &versionInfo{
		Version:   build.Version,
		BuiltBy:   build.BuiltBy,
		BuildDate: build.BuildDate,
		Commit:    build.Commit,
		Go: runtimeInfo{
			Os:      runtime.GOOS,
			Arch:    runtime.GOARCH,
			Version: runtime.Version(),
		},
		asJson: cmd.Flag("json", "Output in JSON format").Bool(),
	}

	cmd.Action(info.Run)
}

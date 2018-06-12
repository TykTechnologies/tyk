package cli

import (
	"fmt"
	"os"

	kingpin "gopkg.in/alecthomas/kingpin.v2"

	"github.com/TykTechnologies/tyk/cli/importer"
	"github.com/TykTechnologies/tyk/cli/lint"
)

const (
	appName = "tyk"
	appDesc = "Tyk Gateway"
)

var (
	// Conf specifies the configuration file path.
	Conf *string
	// Port specifies the listen port.
	Port *string
	// MemProfile enables memory profiling.
	MemProfile *bool
	// CPUProfile enables CPU profiling.
	CPUProfile *bool
	// BlockProfile enables block profiling.
	BlockProfile *bool
	// MutexProfile enables block profiling.
	MutexProfile *bool
	// HTTPProfile exposes a HTTP endpoint for accessing profiling data.
	HTTPProfile *bool
	// DebugMode sets the log level to debug mode.
	DebugMode *bool
	// LogInstrumentation outputs instrumentation data to stdout.
	LogInstrumentation *bool

	app *kingpin.Application
)

// Init sets all flags and subcommands.
func Init(version string, confPaths []string) {
	app = kingpin.New(appName, appDesc)
	app.HelpFlag.Short('h')
	app.Version(version)

	// Start/default command:
	startCmd := app.Command("start", "Starts the Tyk Gateway")
	Conf = startCmd.Flag("conf", "load a named configuration file").PlaceHolder("FILE").String()
	Port = startCmd.Flag("port", "listen on PORT (overrides config file)").String()
	MemProfile = startCmd.Flag("memprofile", "generate a memory profile").Bool()
	CPUProfile = startCmd.Flag("cpuprofile", "generate a cpu profile").Bool()
	BlockProfile = startCmd.Flag("blockprofile", "generate a block profile").Bool()
	MutexProfile = startCmd.Flag("mutexprofile", "generate a mutex profile").Bool()
	HTTPProfile = startCmd.Flag("httpprofile", "expose runtime profiling data via HTTP").Bool()
	DebugMode = startCmd.Flag("debug", "enable debug mode").Bool()
	LogInstrumentation = startCmd.Flag("log-intrumentation", "output intrumentation output to stdout").Bool()

	startCmd.Action(func(ctx *kingpin.ParseContext) error {
		return nil
	})
	startCmd.Default()

	// Linter:
	lintCmd := app.Command("lint", "Runs a linter on Tyk configuration file")
	lintCmd.Action(func(c *kingpin.ParseContext) error {
		path, lines, err := lint.Run(confPaths)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if len(lines) == 0 {
			fmt.Printf("found no issues in %s\n", path)
			return nil
		}
		fmt.Printf("issues found in %s:\n", path)
		for _, line := range lines {
			fmt.Println(line)
		}
		os.Exit(1)
		return nil
	})

	// Import command:
	importer.AddTo(app)
}

// Parse parses the command-line arguments.
func Parse() {
	kingpin.MustParse(app.Parse(os.Args[1:]))
}

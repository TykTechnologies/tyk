package lint

import (
	"fmt"
	"net"
	"os"

	"github.com/TykTechnologies/tyk/config"
)

// TODO: reuse this from somewhere, like the config package
var confPaths = []string{
	"tyk.conf",
	// TODO: add ~/.config/tyk/tyk.conf here?
	"/etc/tyk/tyk.conf",
}

// Run will lint the configuration file. It will return a list of
// warnings and an error, if any happened.
func Run() ([]string, error) {
	var conf config.Config
	if err := config.Load(confPaths, &conf); err != nil {
		return nil, err
	}
	return allWarnings(&conf), nil
}

func allWarnings(conf *config.Config) []string {
	var lines []string
	lines = append(lines, listenAddrPort(conf)...)
	lines = append(lines, existingPaths(conf)...)
	return lines
}

func listenAddrPort(conf *config.Config) (warns []string) {
	if _, port, _ := net.SplitHostPort(conf.ListenAddress); port != "" {
		warns = append(warns, "listen port should be set in listen_port")
	}
	return
}

func existingPaths(conf *config.Config) (warns []string) {
	// TODO: check which are files and dirs. ensure readability?
	fields := []struct {
		name, path string
	}{
		{"template_path", conf.TemplatePath},
		{"tyk_js_path", conf.TykJSPath},
		{"middleware_path", conf.MiddlewarePath},
		{"app_path", conf.AppPath},
	}
	for _, field := range fields {
		if field.path == "" {
			continue // not set
		}
		if _, err := os.Stat(field.path); os.IsNotExist(err) {
			warns = append(warns, fmt.Sprintf("%s %q does not exist",
				field.name, field.path))
		}
	}
	return
}

package lint

import (
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
	return lines
}

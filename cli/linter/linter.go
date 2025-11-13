package linter

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/service/gojsonschema"
)

// Run will lint the configuration file. It will return the path to the
// config file that was checked, a list of warnings and an error, if any
// happened.
func Run(schm string, paths []string) (string, []string, error) {
	addFormats(&gojsonschema.FormatCheckers)
	var conf config.Config
	if err := config.Load(paths, &conf); err != nil {
		return "", nil, err
	}
	schemaLoader := gojsonschema.NewBytesLoader([]byte(schm))

	var orig map[string]interface{}
	f, err := os.Open(conf.Private.OriginalPath)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&orig); err != nil {
		return "", nil, err
	}
	if v, ok := orig["Monitor"]; ok {
		// As the old confs wrongly capitalized this key. Would
		// be fixed by WriteConf below, but we want the JSON
		// schema to not flag this error.
		orig["monitor"] = v
		delete(orig, "Monitor")
	}

	fileLoader := gojsonschema.NewGoLoader(orig)
	result, err := gojsonschema.Validate(schemaLoader, fileLoader)
	if err != nil {
		return "", nil, err
	}

	// ensure it's well formatted and the keys are all lowercase
	if err := config.WriteConf(conf.Private.OriginalPath, &conf); err != nil {
		return "", nil, err
	}

	return conf.Private.OriginalPath, resultWarns(result), nil
}

type stringFormat func(string) bool

func (f stringFormat) IsFormat(v interface{}) bool {
	s := v.(string)
	if s == "" {
		return true // empty string is ok
	}
	return f(s)
}

func addFormats(chain *gojsonschema.FormatCheckerChain) {
	chain.Add("path", stringFormat(func(path string) bool {
		_, err := os.Stat(path)
		return err == nil // must be accessible
	}))
	chain.Add("host-no-port", stringFormat(func(host string) bool {
		_, port, err := net.SplitHostPort(host)
		var a *net.AddrError
		if errors.As(err, &a) && a.Err == "missing port in address" {
			// port being missing is ok
			err = nil
		}
		return err == nil && port == "" // valid host with no port
	}))
}

func resultWarns(result *gojsonschema.Result) []string {
	warns := result.Errors()
	strs := make([]string, len(warns))
	for i, warn := range warns {
		ferr, ok := warn.(*gojsonschema.DoesNotMatchFormatError)
		if !ok {
			strs[i] = warn.String()
			continue
		}
		// We need this since formats can only return bools, not
		// custom errors/messages.
		var desc string
		switch format := ferr.Details()["format"].(string); format {
		case "path":
			desc = "Path does not exist or is not accessible"
		case "host-no-port":
			desc = "Address should be a host without port"
		default:
			panic(fmt.Sprintf("unexpected format type: %q", format))
		}
		ferr.SetDescription(desc)
		strs[i] = ferr.String()
	}
	return strs
}

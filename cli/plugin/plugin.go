package plugin

//lint:file-ignore faillint This file should be ignored by faillint (fmt in use).

import (
	"fmt"
	"strings"

	kingpin "github.com/alecthomas/kingpin/v2"

	"github.com/TykTechnologies/tyk/goplugin"
)

const (
	cmdName = "plugin"
	cmdDesc = "Load plugin test"
)

type pluginLoader struct {
	file   *string
	symbol *string
}

// Load tries to load a plugin
func (p *pluginLoader) Load(_ *kingpin.ParseContext) (err error) {
	defer func() {
		if thrown := recover(); thrown != nil {
			err = fmt.Errorf("unexpected panic: %v", thrown)
		}
	}()

	err = p.load()
	return
}

func (p *pluginLoader) load() error {
	for _, filename := range strings.Split(*p.file, ",") {
		funcSymbol, err := goplugin.GetSymbol(filename, *p.symbol)
		if err != nil {
			return fmt.Errorf("unexpected error: %w", err)
		}

		fmt.Printf("[file=%s, symbol=%s] loaded ok, got %v\n", filename, *p.symbol, funcSymbol)
	}
	return nil
}

func (p *pluginLoader) info(message string) {
}

var loader = &pluginLoader{}

// AddTo initializes an importer object.
func AddTo(app *kingpin.Application) {
	cmd := app.Command(cmdName, cmdDesc)

	buildCmd := cmd.Command("load", "Load a plugin")
	loader.file = buildCmd.Flag("file", "Key for bundle signature").Short('f').String()
	loader.symbol = buildCmd.Flag("symbol", "Function symbol name").Short('s').String()
	buildCmd.Action(loader.Load)
}

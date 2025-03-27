package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/buger/jsonparser"
	_ "github.com/warpstreamlabs/bento/public/components/io"
	_ "github.com/warpstreamlabs/bento/public/components/kafka"
	"github.com/warpstreamlabs/bento/public/service"
)

const defaultOutput = "bento-config-schema.json"

var result = []byte(`{}`)

var properties = []string{
	"http",
	"input",
	"input_resources",
	"output",
	"output_resources",
	"processor_resources",
	"shutdown_delay",
	"shutdown_timeout",
}

var definitions = []string{
	"processor",
	"scanner",
}

var supportedSources = []string{
	"broker",
	"http_client",
	"http_server",
	"kafka",
}

func printErrorAndExit(err error) {
	_, _ = fmt.Fprint(os.Stdout, err)
	os.Exit(1)
}

func findTemplate(kind string, data []byte) ([]byte, error) {
	kindData, _, _, err := jsonparser.Get(data, kind, "allOf")
	if err != nil {
		return nil, err
	}

	var template []byte
	_, err = jsonparser.ArrayEach(kindData, func(value []byte, _ jsonparser.ValueType, _ int, _ error) {
		_, _, _, getErr := jsonparser.Get(value, "properties")
		if errors.Is(getErr, jsonparser.KeyPathNotFoundError) {
			// continue
			return
		}
		if getErr != nil {
			printErrorAndExit(getErr)
		}
		template = value
	})
	return template, err
}

func scanProperties(data []byte) error {
	return jsonparser.ObjectEach(data, func(key []byte, value []byte, _ jsonparser.ValueType, _ int) error {
		var err error
		for _, property := range properties {
			if string(key) == property {
				result, err = jsonparser.Set(result, value, "properties", property)
				if err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func insertDefinitions(data []byte) error {
	for _, kind := range []string{"input", "output"} {
		template, err := findTemplate(kind, data)
		if err != nil {
			return err
		}
		result, err = jsonparser.Set(result, template, "definitions", kind)
		if err != nil {
			return err
		}

		err = scanDefinitionsForKind(kind, data)
		if err != nil {
			return err
		}
	}
	return nil
}

func scanDefinitions(data []byte) error {
	err := jsonparser.ObjectEach(data, func(key []byte, value []byte, _ jsonparser.ValueType, _ int) error {
		var err error
		for _, definition := range definitions {
			if string(key) == definition {
				result, err = jsonparser.Set(result, value, "definitions", definition)
				if err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	return insertDefinitions(data)
}

func insertDefinitionKind(kind string, anyOfItems []byte) error {
	_, err := jsonparser.ArrayEach(anyOfItems, func(value []byte, _ jsonparser.ValueType, _ int, _ error) {
		for _, source := range supportedSources {
			var data []byte
			var jsonErr error
			data, _, _, jsonErr = jsonparser.Get(value, "properties", source)
			if errors.Is(jsonErr, jsonparser.KeyPathNotFoundError) {
				continue
			}
			if jsonErr != nil {
				printErrorAndExit(jsonErr)
				return
			}

			result, jsonErr = jsonparser.Set(result, data, "definitions", kind, "properties", source)
			if jsonErr != nil {
				printErrorAndExit(jsonErr)
				return
			}
		}
	})
	return err
}

func scanDefinitionsForKind(kind string, data []byte) error {
	bentoInputs, dataType, _, err := jsonparser.Get(data, kind, "allOf")
	if err != nil {
		return err
	}
	if dataType != jsonparser.Array {
		return fmt.Errorf("expected array but got %s", dataType)
	}

	_, err = jsonparser.ArrayEach(bentoInputs, func(value []byte, dataType jsonparser.ValueType, _ int, _ error) {
		if dataType != jsonparser.Object {
			return
		}

		anyOfItems, _, _, getErr := jsonparser.Get(value, "anyOf")
		if errors.Is(getErr, jsonparser.KeyPathNotFoundError) {
			// Continue
			return
		}
		if getErr != nil {
			printErrorAndExit(getErr)
		}

		insertErr := insertDefinitionKind(kind, anyOfItems)
		if insertErr != nil {
			printErrorAndExit(insertErr)
		}
	})
	return err
}

func saveFile(outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("error creating file on the disk: %w", err)
	}

	buf := bytes.NewBuffer(nil)
	err = json.Indent(buf, result, "", "  ")
	if err != nil {
		return fmt.Errorf("error indenting bento configuration validator: %w", err)
	}

	_, err = file.Write(buf.Bytes())
	if err != nil {
		return fmt.Errorf("error writing to file on the disk: %w", err)
	}

	err = file.Sync()
	if err != nil {
		return fmt.Errorf("error running fsync on the file: %w", err)
	}

	err = file.Close()
	if err != nil {
		return fmt.Errorf("error closing file on the disk: %w", err)
	}
	return nil
}

func generateBentoConfigSchema(output string) error {
	data, err := service.GlobalEnvironment().FullConfigSchema("", "").MarshalJSONSchema()
	if err != nil {
		return fmt.Errorf("error marshaling bento schema: %w", err)
	}

	err = jsonparser.ObjectEach(data, func(key []byte, value []byte, _ jsonparser.ValueType, _ int) error {
		if string(key) == "properties" {
			result, err = jsonparser.Set(result, []byte("{}"), "properties")
			if err != nil {
				return err
			}
			return scanProperties(value)
		} else if string(key) == "definitions" {
			result, err = jsonparser.Set(result, []byte("{}"), "definitions")
			if err != nil {
				return err
			}
			return scanDefinitions(value)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("error generating bento configuration validator: %w", err)
	}

	return saveFile(output)
}

func usage() {
	var msg = `Usage: generate_bent_config_schema [options] ...

This program generates a JSON schema for the Input/Output resources Tyk supports.

Options:
  -h, --help    Print this message and exit.
  -o, --output  Path to save the generated schema. 
                Default is '%s' in the current working folder.
`
	_, err := fmt.Fprintf(os.Stdout, msg, defaultOutput)
	if err != nil {
		panic(err)
	}
}

type arguments struct {
	help   bool
	output string
}

/*
How to use this program?

generate_bento_config_schema generates a JSON schema for the Input/Output resources we support.

Simply,

go run generate_bento_config.go

It'll generate a `bento-config-schema.json` file in the current working folder. You can also set
an output path via -output-path <string> parameter.

Run via task runner:

task generate-bento-config-validator-schema

The task will automatically update `apidef/streams/bento/schema/bento-config-schema.json` file.
*/
func main() {
	/*
			How to add a new Input/Output source
			1- Import the related component for its side effects, for example if you want to produce a JSON schema that supports redis component,
			   you can import it like the following:

		       _ "github.com/warpstreamlabs/bento/public/components/redis"

			2- Add its name to `supportedSources` slice. You should know that some components exposes different input/output sources
			   For example, components/kafka exposes `kafka` and `kafka_franz`. You need to dig into the Bento's codebase to understand
		       which input/output is exposed by a component.
	*/

	// Importing a small number of components was preferred instead of importing `components/all` because importing all components
	// results in a huge `definitions/processor` object and there is no way to know which processor are used by the components we support.

	var args arguments
	f := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	f.SetOutput(ioutil.Discard)
	f.BoolVar(&args.help, "h", false, "")
	f.BoolVar(&args.help, "help", false, "")
	f.StringVar(&args.output, "output", defaultOutput, "")
	f.StringVar(&args.output, "o", defaultOutput, "")
	if err := f.Parse(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintf(os.Stdout, "failed to parse CLI arguments: %v\n", err)
		usage()
		os.Exit(1)
	}

	if args.help {
		usage()
		return
	}

	if err := generateBentoConfigSchema(args.output); err != nil {
		printErrorAndExit(err)
	}
	_, _ = fmt.Fprintf(os.Stdout, "Bento schema generated in '%s'\n", args.output)
}

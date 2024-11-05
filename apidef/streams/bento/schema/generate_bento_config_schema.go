package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
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

var supportedItems = []string{
	"broker",
	"http_client",
	"http_server",
	"kafka",
}

func printErrorAndExit(err error) {
	_, _ = fmt.Fprint(os.Stderr, err)
	os.Exit(1)
}

func findTemplate(kind string, data []byte) ([]byte, error) {
	kindData, _, _, err := jsonparser.Get(data, kind, "allOf")
	if err != nil {
		return nil, err
	}

	var template []byte
	_, err = jsonparser.ArrayEach(kindData, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		_, _, _, err = jsonparser.Get(value, "properties")
		if errors.Is(err, jsonparser.KeyPathNotFoundError) {
			// continue
			err = nil
			return
		}
		if err != nil {
			printErrorAndExit(err)
		}
		template = value
	})
	return template, err
}

func scanProperties(data []byte) error {
	return jsonparser.ObjectEach(data, func(key []byte, value []byte, dataType jsonparser.ValueType, offset int) error {
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
	err := jsonparser.ObjectEach(data, func(key []byte, value []byte, dataType jsonparser.ValueType, offset int) error {
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
	_, err := jsonparser.ArrayEach(anyOfItems, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		for _, item := range supportedItems {
			var data []byte
			var jsonErr error
			data, _, _, jsonErr = jsonparser.Get(value, "properties", item)
			if errors.Is(jsonErr, jsonparser.KeyPathNotFoundError) {
				continue
			}
			if jsonErr != nil {
				err = jsonErr
				return
			}

			result, jsonErr = jsonparser.Set(result, data, "definitions", kind, "properties", item)
			if jsonErr != nil {
				err = jsonErr
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

	_, err = jsonparser.ArrayEach(bentoInputs, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		if dataType != jsonparser.Object {
			return
		}

		anyOfItems, _, _, err := jsonparser.Get(value, "anyOf")
		if errors.Is(err, jsonparser.KeyPathNotFoundError) {
			// The following lines mean `continue` in jsonparser's context.
			err = nil
			return
		}
		if err != nil {
			printErrorAndExit(err)
		}

		err = insertDefinitionKind(kind, anyOfItems)
		if err != nil {
			printErrorAndExit(err)
		}
	})
	return err
}

func saveFile(outputPath string) {
	file, err := os.Create(outputPath)
	if err != nil {
		printErrorAndExit(fmt.Errorf("error creating file on the disk: %w", err))
	}

	buf := bytes.NewBuffer(nil)
	err = json.Indent(buf, result, "", "  ")
	if err != nil {
		printErrorAndExit(fmt.Errorf("error indenting bento configuration validator: %w", err))
	}

	_, err = file.Write(buf.Bytes())
	if err != nil {
		printErrorAndExit(fmt.Errorf("error writing to file on the disk: %w", err))
	}

	err = file.Sync()
	if err != nil {
		printErrorAndExit(fmt.Errorf("error running fsync on the file: %w", err))
	}

	err = file.Close()
	if err != nil {
		printErrorAndExit(fmt.Errorf("error closing file on the disk: %w", err))
	}

	fmt.Printf("Bento schema generated in '%s'\n", file.Name())
}

/*
How to use this program?

generate_bento_config_schema generates a JSON schema for the Input/Output resources we support.

Simply,

go run generate_bento_config.go

It'll generate a `bento-config-schema.json` file in the current working folder. You can also set
an output path via -output-path <string> parameter.
*/
func main() {
	/*
			How to add a new Input/Output source
			1- Import the related component for its side effects, for example if you want to produce a JSON schema that supports redis component,
			   you can import it like the following:

		       _ "github.com/warpstreamlabs/bento/public/components/redis"

			2- Add its name to `supportedItems` slice. You should know that some components exposes different input/output sources
			   For example, components/kafka exposes `kafka` and `kafka_franz`. You need to dig into the Bento's codebase to understand
		       which input/output is exposed by a component.
	*/

	// Importing a small number of components was preferred instead of importing `components/all` because importing all components
	// results in a huge `definitions/processor` object and there is no way to know which processor are used by the components we support.

	var outputPath string
	flag.StringVar(&outputPath, "output-path", defaultOutput, "Path to save the output")
	flag.Parse()

	data, err := service.GlobalEnvironment().FullConfigSchema("", "").MarshalJSONSchema()
	if err != nil {
		printErrorAndExit(fmt.Errorf("error marshaling bento schema: %w", err))
	}

	err = jsonparser.ObjectEach(data, func(key []byte, value []byte, dataType jsonparser.ValueType, offset int) error {
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
		printErrorAndExit(fmt.Errorf("error generating bento configuration validator: %w", err))
	}

	saveFile(outputPath)
}

package oas

import (
	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	cmdConvertToTykName = "convertToTyk"
	cmdConvertToTykDesc = "Converts OAS to Tyk API Definition format"
	cmdConvertToOASName = "convertToSwagger"
	cmdConvertToOASDesc = "Converts Tyk API Definition to OAS format"
)

var (
	converter *Converter
	//errUnknownMode = errors.New("Unknown mode")
)

type Converter struct {
	input   *string
	version *string
	//swaggerMode    *bool
	//swagger oas.Converter
}

/*func (c Converter) TykAPIDefinitionToSwagger(ctx *kingpin.ParseContext) error {
	var api apidef.APIDefinition
	apiInBytes, _ := ioutil.ReadFile(*c.input)
	_ = json.Unmarshal(apiInBytes, &api)

	var convertedSwagger openapi3.Swagger
	c.swagger.TykAPIDefinitionToSwagger(api, &convertedSwagger, "Default")

	swaggerJSON, _ := json.MarshalIndent(&convertedSwagger, "", " ")
	swaggerYAML, _ := yaml.JSONToYAML(swaggerJSON)

	resName := "converted-" + strings.TrimSuffix(*c.input, filepath.Ext(*c.input)) + ".yml"
	_ = ioutil.WriteFile(resName, swaggerYAML, 0644)

	return nil
}

func (c Converter) SwaggerToTykAPIDefinition(ctx *kingpin.ParseContext) error {
	var swaggerAPI openapi3.Swagger
	swaggerYAML, _ := ioutil.ReadFile(*c.input)
	swaggerJSON, _ := yaml.YAMLToJSON(swaggerYAML)
	_ = json.Unmarshal(swaggerJSON, &swaggerAPI)

	convertedTykAPI := c.swagger.SwaggerToTykAPIDefinition(swaggerAPI, "Default")

	apiJSON, _ := json.MarshalIndent(convertedTykAPI, "", "  ")

	resName := "converted-" + strings.TrimSuffix(*c.input, filepath.Ext(*c.input)) + ".json"

	_ = ioutil.WriteFile(resName, apiJSON, 0644)

	return nil
}

func init() {
	converter = &Converter{swagger: oas.Converter{}}
}*/

// AddTo initializes an oas object.
func AddTo(app *kingpin.Application) {
	/*cmd := app.Command(cmdConvertToOASName, cmdConvertToOASDesc)
	converter.input = cmd.Arg("input", "e.g. tyk-api.json, tyk-swagger.json").String()
	cmd.Action(converter.TykAPIDefinitionToSwagger)

	cmd2 := app.Command(cmdConvertToTykName, cmdConvertToTykDesc)
	converter.input = cmd2.Arg("input", "e.g. tyk-api.json, tyk-swagger.json").String()
	cmd2.Action(converter.SwaggerToTykAPIDefinition)*/
}

package importer

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	log "github.com/Sirupsen/logrus"

	kingpin "gopkg.in/alecthomas/kingpin.v2"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/importer"
)

const (
	cmdName = "import"
	cmdDesc = "Imports a BluePrint/Swagger file"
)

var (
	imp            *Importer
	errUnknownMode = errors.New("Unknown mode")
)

// Importer wraps the import functionality.
type Importer struct {
	input          *string
	swaggerMode    *bool
	bluePrintMode  *bool
	createAPI      *bool
	orgID          *string
	upstreamTarget *string
	asMock         *bool
	forAPI         *string
	asVersion      *string
}

func init() {
	imp = &Importer{}
}

// AddTo initializes an importer object.
func AddTo(app *kingpin.Application) {
	cmd := app.Command(cmdName, cmdDesc)
	imp.input = cmd.Arg("input file", "e.g. blueprint.json, swagger.json, etc.").String()
	imp.swaggerMode = cmd.Flag("swagger", "Use Swagger mode").Bool()
	imp.bluePrintMode = cmd.Flag("blueprint", "Use BluePrint mode").Bool()
	imp.createAPI = cmd.Flag("create-api", "Creates a new API definition from the blueprint").Bool()
	imp.orgID = cmd.Flag("org-id", "assign the API Definition to this org_id (required with create-api").String()
	imp.upstreamTarget = cmd.Flag("upstream-target", "set the upstream target for the definition").PlaceHolder("URL").String()
	imp.asMock = cmd.Flag("as-mock", "creates the API as a mock based on example fields").Bool()
	imp.forAPI = cmd.Flag("for-api", "adds blueprint to existing API Definition as version").PlaceHolder("PATH").String()
	imp.asVersion = cmd.Flag("as-version", "the version number to use when inserting").PlaceHolder("VERSION").String()
	cmd.Action(imp.Import)
}

// Import performs the import process.
func (i *Importer) Import(ctx *kingpin.ParseContext) (err error) {
	if *i.swaggerMode {
		err = i.handleSwaggerMode()
		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}
	} else if *i.bluePrintMode {
		err = i.handleBluePrintMode()
		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}
	} else {
		log.Fatal(errUnknownMode)
		os.Exit(1)
	}
	os.Exit(0)
	return nil
}

func (i *Importer) handleBluePrintMode() error {
	if !*i.createAPI {
		// Different branch, here we need an API Definition to modify
		if *i.forAPI == "" {
			return fmt.Errorf("If adding to an API, the path to the definition must be listed")
		}

		if *i.asVersion == "" {
			return fmt.Errorf("No version defined for this import operation, please set an import ID using the --as-version flag")
		}

		defFromFile, err := i.apiDefLoadFile(*i.forAPI)
		if err != nil {
			return fmt.Errorf("failed to load and decode file data for API Definition: %v", err)
		}

		bp, err := i.bluePrintLoadFile(*i.input)
		if err != nil {
			return fmt.Errorf("File load error: %v", err)
		}
		versionData, err := bp.ConvertIntoApiVersion(*i.asMock)
		if err != nil {
			return fmt.Errorf("onversion into API Def failed: %v", err)
		}

		if err := bp.InsertIntoAPIDefinitionAsVersion(versionData, defFromFile, *i.asVersion); err != nil {
			return fmt.Errorf("Insertion failed: %v", err)
		}

		i.printDef(defFromFile)

	}

	if *i.upstreamTarget == "" && *i.orgID == "" {
		return fmt.Errorf("No upstream target or org ID defined, these are both required")
	}

	// Create the API with the blueprint
	bp, err := i.bluePrintLoadFile(*i.input)
	if err != nil {
		return fmt.Errorf("File load error: %v", err)
	}

	def, err := bp.ToAPIDefinition(*i.orgID, *i.upstreamTarget, *i.asMock)
	if err != nil {
		return fmt.Errorf("Failed to create API Definition from file")
	}

	i.printDef(def)
	return nil
}

func (i *Importer) handleSwaggerMode() error {
	if *i.createAPI {
		if *i.upstreamTarget != "" && *i.orgID != "" {
			// Create the API with the blueprint
			s, err := i.swaggerLoadFile(*i.input)
			if err != nil {
				return fmt.Errorf("File load error: %v", err)
			}

			def, err := s.ToAPIDefinition(*i.orgID, *i.upstreamTarget, *i.asMock)
			if err != nil {
				return fmt.Errorf("Failed to create API Defintition from file")
			}

			i.printDef(def)
			return nil
		}

		return fmt.Errorf("No upstream target or org ID defined, these are both required")

	}

	// Different branch, here we need an API Definition to modify
	if *i.forAPI == "" {
		return fmt.Errorf("If adding to an API, the path to the definition must be listed")
	}

	if *i.asVersion == "" {
		return fmt.Errorf("No version defined for this import operation, please set an import ID using the --as-version flag")
	}

	defFromFile, err := i.apiDefLoadFile(*i.forAPI)
	if err != nil {
		return fmt.Errorf("failed to load and decode file data for API Definition: %v", err)
	}

	s, err := i.swaggerLoadFile(*i.input)
	if err != nil {
		return fmt.Errorf("File load error: %v", err)
	}

	versionData, err := s.ConvertIntoApiVersion(*i.asMock)
	if err != nil {
		return fmt.Errorf("Conversion into API Def failed: %v", err)
	}

	if err := s.InsertIntoAPIDefinitionAsVersion(versionData, defFromFile, *i.asVersion); err != nil {
		return fmt.Errorf("Insertion failed: %v", err)
	}

	i.printDef(defFromFile)

	return nil
}

func (i *Importer) printDef(def *apidef.APIDefinition) {
	asJSON, err := json.MarshalIndent(def, "", "    ")
	if err != nil {
		log.Error("Marshalling failed: ", err)
	}

	// The id attribute is for BSON only and breaks the parser if it's empty, cull it here.
	fixed := strings.Replace(string(asJSON), `    "id": "",`, "", 1)
	fmt.Println(fixed)
}

func (i *Importer) swaggerLoadFile(path string) (*importer.SwaggerAST, error) {
	swagger, err := importer.GetImporterForSource(importer.SwaggerSource)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if err := swagger.LoadFrom(f); err != nil {
		return nil, err
	}

	return swagger.(*importer.SwaggerAST), nil
}

func (i *Importer) bluePrintLoadFile(path string) (*importer.BluePrintAST, error) {
	blueprint, err := importer.GetImporterForSource(importer.ApiaryBluePrint)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if err := blueprint.LoadFrom(f); err != nil {
		return nil, err
	}

	return blueprint.(*importer.BluePrintAST), nil
}

func (i *Importer) apiDefLoadFile(path string) (*apidef.APIDefinition, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	def := &apidef.APIDefinition{}
	if err := json.NewDecoder(f).Decode(&def); err != nil {
		return nil, err
	}
	return def, nil
}

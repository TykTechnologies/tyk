package importer

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	apiimporter "github.com/TykTechnologies/tyk/apidef/importer"

	kingpin "github.com/alecthomas/kingpin/v2"
)

// Verifies: STK-REQ-026, SYS-REQ-114, SW-REQ-101
// SYS-REQ-114:nominal:nominal
// SW-REQ-101:nominal:nominal
// SW-REQ-101:boundary:nominal
// SW-REQ-101:error_handling:nominal
// SW-REQ-101:error_handling:negative
// STK-REQ-026:error_handling:negative
// MCDC SYS-REQ-114: cli_import_operation_requested=F, cli_import_result_determined=F => TRUE
// MCDC SYS-REQ-114: cli_import_operation_requested=T, cli_import_result_determined=T => TRUE
//
//mcdc:ignore SYS-REQ-114: cli_import_operation_requested=T, cli_import_result_determined=F => FALSE -- violation row is the negation of the local CLI importer result guarantee; these tests assert requested importer wrapper operations either register command inputs, return formatted output, load/decode local files, or return explicit local errors [category: defensive] [reviewed: agent:codex]
func TestCLIImporterReqProof_CommandRegistrationAndValidation(t *testing.T) {
	t.Run("command registration binds import flags and input argument", func(t *testing.T) {
		prevImp := imp
		imp = &Importer{}
		t.Cleanup(func() {
			imp = prevImp
		})

		app := kingpin.New("tyk-cli", "")
		AddTo(app)

		cmd := commandModel(t, app, cmdName)

		require.Len(t, cmd.Args, 1)
		assert.Equal(t, "input file", cmd.Args[0].Name)
		assert.ElementsMatch(t, []string{
			"swagger",
			"blueprint",
			"wsdl",
			"port-names",
			"create-api",
			"org-id",
			"upstream-target",
			"as-mock",
			"for-api",
			"as-version",
		}, flagNames(cmd))
		require.NotNil(t, imp.input)
		require.NotNil(t, imp.swaggerMode)
		require.NotNil(t, imp.bluePrintMode)
		require.NotNil(t, imp.wsdlMode)
		require.NotNil(t, imp.createAPI)
		require.NotNil(t, imp.orgID)
		require.NotNil(t, imp.upstreamTarget)
		require.NotNil(t, imp.forAPI)
		require.NotNil(t, imp.asVersion)
	})

	tests := []struct {
		name           string
		createAPI      bool
		orgID          string
		upstreamTarget string
		forAPI         string
		asVersion      string
		wantErr        string
	}{
		{
			name:           "create API accepts required organization and upstream target",
			createAPI:      true,
			orgID:          "org-1",
			upstreamTarget: "https://upstream.example.com",
		},
		{
			name:      "create API rejects missing organization and upstream target",
			createAPI: true,
			wantErr:   "no upstream target or org ID defined, these are both required",
		},
		{
			name:      "version insert accepts target API and version",
			forAPI:    "api.json",
			asVersion: "v1",
		},
		{
			name:    "version insert rejects missing target API",
			wantErr: "if adding to an API, the path to the definition must be listed",
		},
		{
			name:    "version insert rejects missing version",
			forAPI:  "api.json",
			wantErr: "no version defined for this import operation, please set an import ID using the --as-version flag",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			importer := testImporter(tt.createAPI, tt.orgID, tt.upstreamTarget, tt.forAPI, tt.asVersion)

			err := importer.validateInput()

			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.EqualError(t, err, tt.wantErr)
		})
	}
}

// Verifies: STK-REQ-026, SYS-REQ-114, SW-REQ-101
// SW-REQ-101:nominal:nominal
// SW-REQ-101:boundary:nominal
func TestCLIImporterReqProof_ProcessPortNames(t *testing.T) {
	tests := []struct {
		name      string
		portNames string
		want      map[string]string
	}{
		{
			name: "empty input returns empty mapping",
			want: map[string]string{},
		},
		{
			name:      "comma-separated service port pairs are mapped",
			portNames: "InventoryService:InventorySoapPort,AdminService:AdminHttpPort",
			want: map[string]string{
				"InventoryService": "InventorySoapPort",
				"AdminService":     "AdminHttpPort",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			portNames := tt.portNames
			importer := &Importer{portNames: &portNames}

			assert.Equal(t, tt.want, importer.processPortNames())
		})
	}
}

// Verifies: STK-REQ-026, SYS-REQ-114, SW-REQ-101
// SW-REQ-101:nominal:nominal
// SW-REQ-101:error_handling:negative
func TestCLIImporterReqProof_FileLoadersAndOutputFormatting(t *testing.T) {
	dir := t.TempDir()
	importer := &Importer{}

	apiDefPath := writeImporterTestFile(t, dir, "api.json", `{"name":"Inventory API","api_id":"inventory"}`)
	apiDef, err := importer.apiDefLoadFile(apiDefPath)
	require.NoError(t, err)
	assert.Equal(t, "Inventory API", apiDef.Name)
	assert.Equal(t, "inventory", apiDef.APIID)

	_, err = importer.apiDefLoadFile(filepath.Join(dir, "missing-api.json"))
	require.Error(t, err)
	malformedAPIPath := writeImporterTestFile(t, dir, "malformed-api.json", `{"name":`)
	_, err = importer.apiDefLoadFile(malformedAPIPath)
	require.Error(t, err)

	swaggerPath := writeImporterTestFile(t, dir, "swagger.json", reqproofCLIImporterSwaggerJSON)
	swagger, err := importer.swaggerLoadFile(swaggerPath)
	require.NoError(t, err)
	assert.IsType(t, &apiimporter.SwaggerAST{}, swagger)

	blueprintPath := writeImporterTestFile(t, dir, "blueprint.json", reqproofCLIImporterBlueprintJSON)
	blueprint, err := importer.bluePrintLoadFile(blueprintPath)
	require.NoError(t, err)
	assert.IsType(t, &apiimporter.BluePrintAST{}, blueprint)

	wsdlPath := writeImporterTestFile(t, dir, "service.wsdl", reqproofCLIImporterWSDL)
	wsdl, err := importer.wsdlLoadFile(wsdlPath)
	require.NoError(t, err)
	assert.IsType(t, &apiimporter.WSDLDef{}, wsdl)

	for _, tt := range []struct {
		name string
		load func(string) error
	}{
		{
			name: "swagger missing file",
			load: func(path string) error {
				_, err := importer.swaggerLoadFile(path)
				return err
			},
		},
		{
			name: "blueprint missing file",
			load: func(path string) error {
				_, err := importer.bluePrintLoadFile(path)
				return err
			},
		},
		{
			name: "wsdl missing file",
			load: func(path string) error {
				_, err := importer.wsdlLoadFile(path)
				return err
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.Error(t, tt.load(filepath.Join(dir, "missing-source")))
		})
	}

	output := captureStdout(t, func() {
		importer.printDef(&apidef.APIDefinition{Name: "Inventory API"})
	})
	assert.Contains(t, output, `"name": "Inventory API"`)
	assert.NotContains(t, output, `"id": ""`)
}

func testImporter(createAPI bool, orgID, upstreamTarget, forAPI, asVersion string) *Importer {
	return &Importer{
		createAPI:      &createAPI,
		orgID:          &orgID,
		upstreamTarget: &upstreamTarget,
		forAPI:         &forAPI,
		asVersion:      &asVersion,
	}
}

func writeImporterTestFile(t testing.TB, dir, name, contents string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(contents), 0600))
	return path
}

func captureStdout(t testing.TB, fn func()) string {
	t.Helper()

	prevStdout := os.Stdout
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = writer
	t.Cleanup(func() {
		os.Stdout = prevStdout
	})

	fn()
	require.NoError(t, writer.Close())
	output, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())
	os.Stdout = prevStdout

	return string(output)
}

func commandModel(t testing.TB, app *kingpin.Application, name string) *kingpin.CmdModel {
	t.Helper()

	for _, cmd := range app.Model().Commands {
		if cmd.Name == name {
			return cmd
		}
	}
	t.Fatalf("command %q was not registered", name)
	return nil
}

func flagNames(cmd *kingpin.CmdModel) []string {
	names := make([]string, 0, len(cmd.Flags))
	for _, flag := range cmd.Flags {
		names = append(names, flag.Name)
	}
	return names
}

const reqproofCLIImporterSwaggerJSON = `{
  "swagger": "2.0",
  "info": {
    "version": "1.0.0",
    "title": "Inventory Swagger"
  },
  "paths": {}
}`

const reqproofCLIImporterBlueprintJSON = `{
  "name": "Inventory API",
  "resourceGroups": []
}`

const reqproofCLIImporterWSDL = `<?xml version="1.0" encoding="UTF-8"?>
<wsdl:definitions
  xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
  xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
  xmlns:http="http://schemas.xmlsoap.org/wsdl/http/"
  xmlns:tns="urn:reqproof"
  targetNamespace="urn:reqproof">
  <wsdl:binding name="InventorySoapBinding" type="tns:InventoryPortType">
    <soap:binding transport="http://schemas.xmlsoap.org/soap/http"/>
    <wsdl:operation name="CreatePet">
      <soap:operation soapAction="create"/>
    </wsdl:operation>
  </wsdl:binding>
  <wsdl:service name="InventoryService">
    <wsdl:port name="InventorySoapPort" binding="tns:InventorySoapBinding">
      <soap:address location="https://inventory.example.com/soap"/>
    </wsdl:port>
  </wsdl:service>
</wsdl:definitions>`

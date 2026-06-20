package importer

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

// Verifies: SYS-REQ-104, SW-REQ-084
// SW-REQ-084:nominal:nominal
// SW-REQ-084:boundary:nominal
// SW-REQ-084:error_handling:negative
// SW-REQ-084:determinism:nominal
func TestWSDLImporterReqProof_ConvertIntoApiVersion(t *testing.T) {
	t.Run("HTTP binding conversion is deterministic and isolated by importer instance", func(t *testing.T) {
		first := loadReqProofWSDL(t, reqproofWSDL)
		first.SetServicePortMapping(map[string]string{"InventoryService": "InventoryHttpPort"})

		version, err := first.ConvertIntoApiVersion(false)
		require.NoError(t, err)

		assert.True(t, version.UseExtendedPaths)
		assert.Equal(t, "1.0.0", version.Name)
		assert.Empty(t, version.ExtendedPaths.Internal)
		assert.Equal(t, []apidef.TrackEndpointMeta{
			{Path: "InventoryService/pets/{petId}", Method: "GET"},
			{Path: "InventoryService/status", Method: "GET"},
		}, version.ExtendedPaths.TrackEndpoints)
		assert.Equal(t, []apidef.URLRewriteMeta{
			{
				Path:         "InventoryService/pets/{petId}",
				Method:       "GET",
				MatchPattern: "(/pets/.*)",
				RewriteTo:    "https://inventory.example.com/http$1",
			},
			{
				Path:         "InventoryService/status",
				Method:       "GET",
				MatchPattern: "(status.*)",
				RewriteTo:    "https://inventory.example.com/http$1",
			},
		}, version.ExtendedPaths.URLRewrite)

		second := loadReqProofWSDL(t, reqproofWSDL)
		second.SetServicePortMapping(map[string]string{"InventoryService": "InventoryHttpPort"})
		again, err := second.ConvertIntoApiVersion(false)
		require.NoError(t, err)
		assert.Equal(t, version, again)

		defaultPort := loadReqProofWSDL(t, reqproofWSDL)
		defaultVersion, err := defaultPort.ConvertIntoApiVersion(false)
		require.NoError(t, err)
		assert.Equal(t, []apidef.TrackEndpointMeta{
			{Path: "InventoryService/CreatePet", Method: "POST"},
		}, defaultVersion.ExtendedPaths.TrackEndpoints)
	})

	t.Run("SOAP 1.2 HTTP transport converts operations as POST rewrites", func(t *testing.T) {
		def := loadReqProofWSDL(t, reqproofWSDL)
		def.SetServicePortMapping(map[string]string{"InventoryService": "InventorySoap12Port"})

		version, err := def.ConvertIntoApiVersion(false)
		require.NoError(t, err)

		assert.Equal(t, []apidef.TrackEndpointMeta{
			{Path: "InventoryService/ReplacePet", Method: "POST"},
		}, version.ExtendedPaths.TrackEndpoints)
		assert.Equal(t, []apidef.URLRewriteMeta{
			{
				Path:         "InventoryService/ReplacePet",
				Method:       "POST",
				MatchPattern: "InventoryService/ReplacePet",
				RewriteTo:    "https://inventory.example.com/soap12",
			},
		}, version.ExtendedPaths.URLRewrite)
	})

	t.Run("conversion rejects unsupported and malformed service shapes", func(t *testing.T) {
		def := loadReqProofWSDL(t, reqproofWSDL)
		def.SetServicePortMapping(map[string]string{"InventoryService": "MissingPort"})
		_, err := def.ConvertIntoApiVersion(false)
		require.Error(t, err)
		assert.EqualError(t, err, "Error processing wsdl file")

		_, err = loadReqProofWSDL(t, reqproofUnsupportedBindingWSDL).ConvertIntoApiVersion(false)
		require.Error(t, err)
		assert.EqualError(t, err, "Error processing wsdl file")

		_, err = loadReqProofWSDL(t, reqproofNoPortWSDL).ConvertIntoApiVersion(false)
		require.Error(t, err)
		assert.EqualError(t, err, "Error processing wsdl file")

		_, err = loadReqProofWSDL(t, reqproofMissingHTTPLocationWSDL).ConvertIntoApiVersion(false)
		require.Error(t, err)
		assert.EqualError(t, err, "Error processing wsdl file")
	})

	assert.Equal(t, "InventoryBinding", trimNamespace("tns:InventoryBinding"))
	assert.Equal(t, "InventoryBinding", trimNamespace("InventoryBinding"))
	assert.Equal(t, "/pets/.*", ReplaceWildCards("/pets/{petId}"))
	assert.Equal(t, "/stores/.*/pets/.*", ReplaceWildCards("/stores/{storeId}/pets/{petId}"))
	assert.Equal(t, "/health", ReplaceWildCards("/health"))
}

// Verifies: SYS-REQ-104, SW-REQ-084
// SW-REQ-084:nominal:nominal
// SW-REQ-084:boundary:boundary
// SW-REQ-084:error_handling:negative
// SW-REQ-084:determinism:nominal
func TestWSDLImporterReqProof_LoadInsertAndBuildAPIDefinition(t *testing.T) {
	t.Run("load rejects malformed root shapes", func(t *testing.T) {
		require.Error(t, (&WSDLDef{}).LoadFrom(strings.NewReader(`<not-wsdl/>`)))
		require.Error(t, (&WSDLDef{}).LoadFrom(strings.NewReader(`<wsdl:definitions xmlns:wsdl="http://www.w3.org/ns/wsdl"/>`)))
		require.Error(t, (&WSDLDef{}).LoadFrom(strings.NewReader(`<wsdl:definitions`)))
	})

	t.Run("insert marks API as versioned and stores the named version", func(t *testing.T) {
		def := &apidef.APIDefinition{VersionData: apidef.VersionData{
			NotVersioned: true,
			Versions:     map[string]apidef.VersionInfo{},
		}}
		version := apidef.VersionInfo{Name: "v1"}

		require.NoError(t, (&WSDLDef{}).InsertIntoAPIDefinitionAsVersion(version, def, "v1"))

		assert.False(t, def.VersionData.NotVersioned)
		assert.Equal(t, version, def.VersionData.Versions["v1"])
	})

	t.Run("API definition shape is stable apart from generated API ID", func(t *testing.T) {
		load := func(t *testing.T) *WSDLDef {
			t.Helper()
			def := loadReqProofWSDL(t, reqproofWSDL)
			def.SetServicePortMapping(map[string]string{"InventoryService": "InventorySoapPort"})
			return def
		}

		first, err := load(t).ToAPIDefinition("org-1", "https://upstream.example.com", true)
		require.NoError(t, err)
		second, err := load(t).ToAPIDefinition("org-1", "https://upstream.example.com", false)
		require.NoError(t, err)

		assert.NotEmpty(t, first.APIID)
		assert.NotEqual(t, first.APIID, second.APIID)
		assert.Equal(t, "InventoryService", first.Name)
		assert.True(t, first.Active)
		assert.True(t, first.UseKeylessAccess)
		assert.Equal(t, "org-1", first.OrgID)
		assert.Equal(t, "version", first.VersionDefinition.Key)
		assert.Equal(t, apidef.HeaderLocation, first.VersionDefinition.Location)
		assert.Equal(t, "/InventoryService/", first.Proxy.ListenPath)
		assert.True(t, first.Proxy.StripListenPath)
		assert.Equal(t, "https://upstream.example.com", first.Proxy.TargetURL)
		assert.False(t, first.VersionData.NotVersioned)
		assert.Equal(t, "1.0.0", first.VersionData.DefaultVersion)
		require.Contains(t, first.VersionData.Versions, "1.0.0")
		assert.Equal(t, first.VersionData.Versions["1.0.0"], second.VersionData.Versions["1.0.0"])
	})

	t.Run("API definition build rejects empty service sets without panicking", func(t *testing.T) {
		_, err := (&WSDLDef{}).ToAPIDefinition("org-1", "https://upstream.example.com", false)
		require.Error(t, err)
		assert.EqualError(t, err, "Error processing wsdl file")
	})
}

func loadReqProofWSDL(t *testing.T, input string) *WSDLDef {
	t.Helper()

	def := &WSDLDef{}
	require.NoError(t, def.LoadFrom(strings.NewReader(input)))
	return def
}

const reqproofWSDL = `<?xml version="1.0" encoding="UTF-8"?>
<wsdl:definitions
  xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
  xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
  xmlns:soap12="http://schemas.xmlsoap.org/wsdl/soap12/"
  xmlns:http="http://schemas.xmlsoap.org/wsdl/http/"
  xmlns:tns="urn:reqproof"
  targetNamespace="urn:reqproof">
  <wsdl:binding name="InventorySoapBinding" type="tns:InventoryPortType">
    <soap:binding transport="http://schemas.xmlsoap.org/soap/http"/>
    <wsdl:operation name="CreatePet">
      <soap:operation soapAction="create"/>
    </wsdl:operation>
  </wsdl:binding>
  <wsdl:binding name="InventoryHttpBinding" type="tns:InventoryPortType">
    <http:binding verb="GET"/>
    <wsdl:operation name="GetPet">
      <http:operation location="/pets/(petId)"/>
      <http:urlReplacement/>
    </wsdl:operation>
    <wsdl:operation name="Status">
      <http:operation location="status"/>
    </wsdl:operation>
  </wsdl:binding>
  <wsdl:binding name="InventorySoap12Binding" type="tns:InventoryPortType">
    <soap12:binding transport="http://schemas.xmlsoap.org/soap/http"/>
    <wsdl:operation name="ReplacePet">
      <soap12:operation soapAction="replace"/>
    </wsdl:operation>
  </wsdl:binding>
  <wsdl:service name="InventoryService">
    <wsdl:port name="InventorySoapPort" binding="tns:InventorySoapBinding">
      <soap:address location="https://inventory.example.com/soap"/>
    </wsdl:port>
    <wsdl:port name="InventoryHttpPort" binding="tns:InventoryHttpBinding">
      <http:address location="https://inventory.example.com/http"/>
    </wsdl:port>
    <wsdl:port name="InventorySoap12Port" binding="tns:InventorySoap12Binding">
      <soap12:address location="https://inventory.example.com/soap12"/>
    </wsdl:port>
  </wsdl:service>
</wsdl:definitions>`

const reqproofUnsupportedBindingWSDL = `<?xml version="1.0" encoding="UTF-8"?>
<wsdl:definitions
  xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
  xmlns:smtp="urn:smtp"
  xmlns:tns="urn:reqproof"
  targetNamespace="urn:reqproof">
  <wsdl:binding name="InventorySMTPBinding" type="tns:InventoryPortType">
    <smtp:binding/>
    <wsdl:operation name="SendPet"/>
  </wsdl:binding>
  <wsdl:service name="InventoryService">
    <wsdl:port name="InventorySMTPPort" binding="tns:InventorySMTPBinding">
      <smtp:address location="smtp://inventory.example.com"/>
    </wsdl:port>
  </wsdl:service>
</wsdl:definitions>`

const reqproofNoPortWSDL = `<?xml version="1.0" encoding="UTF-8"?>
<wsdl:definitions
  xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
  targetNamespace="urn:reqproof">
  <wsdl:service name="InventoryService"/>
</wsdl:definitions>`

const reqproofMissingHTTPLocationWSDL = `<?xml version="1.0" encoding="UTF-8"?>
<wsdl:definitions
  xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
  xmlns:http="http://schemas.xmlsoap.org/wsdl/http/"
  xmlns:tns="urn:reqproof"
  targetNamespace="urn:reqproof">
  <wsdl:binding name="InventoryHttpBinding" type="tns:InventoryPortType">
    <http:binding verb="GET"/>
    <wsdl:operation name="GetPet">
      <http:operation/>
    </wsdl:operation>
  </wsdl:binding>
  <wsdl:service name="InventoryService">
    <wsdl:port name="InventoryHttpPort" binding="tns:InventoryHttpBinding">
      <http:address location="https://inventory.example.com/http"/>
    </wsdl:port>
  </wsdl:service>
</wsdl:definitions>`

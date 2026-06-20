package importer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Verifies: SYS-REQ-104, SW-REQ-082
// SW-REQ-082:nominal:nominal
// SW-REQ-082:boundary:nominal
// SW-REQ-082:error_handling:negative
// SW-REQ-082:determinism:nominal
func TestImporterDispatcherReqProof_GetImporterForSource(t *testing.T) {
	tests := []struct {
		name       string
		source     APIImporterSource
		assertType func(t *testing.T, importer APIImporter)
	}{
		{
			name:   "apiary blueprint",
			source: ApiaryBluePrint,
			assertType: func(t *testing.T, importer APIImporter) {
				t.Helper()
				assert.IsType(t, &BluePrintAST{}, importer)
			},
		},
		{
			name:   "swagger",
			source: SwaggerSource,
			assertType: func(t *testing.T, importer APIImporter) {
				t.Helper()
				assert.IsType(t, &SwaggerAST{}, importer)
			},
		},
		{
			name:   "wsdl",
			source: WSDLSource,
			assertType: func(t *testing.T, importer APIImporter) {
				t.Helper()
				assert.IsType(t, &WSDLDef{}, importer)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first, err := GetImporterForSource(tt.source)
			require.NoError(t, err)
			require.NotNil(t, first)
			tt.assertType(t, first)

			second, err := GetImporterForSource(tt.source)
			require.NoError(t, err)
			assert.IsType(t, first, second)
			assert.NotSame(t, first, second)
		})
	}

	importer, err := GetImporterForSource(APIImporterSource("unknown"))
	require.Error(t, err)
	assert.Nil(t, importer)
	assert.EqualError(t, err, "source not matched, failing")
}

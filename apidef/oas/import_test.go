package oas_test

import (
	"embed"
	"encoding/json"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
)

//go:embed testdata/urlRewrite.json testdata/petstore-no-responses.json
var oasTestAPIs embed.FS

// TestLoad_URLRewrite(t *testing.T)
//
// - Loads the urlRewrite OAS spec with tyk extensions
func TestLoad_URLRewrite(t *testing.T) {
	oasContents, err := oasTestAPIs.ReadFile("testdata/urlRewrite.json")
	assert.NoError(t, err)
	assert.NotNil(t, oasContents)

	var urlRewriteOAS oas.OAS
	assert.NoError(t, json.Unmarshal(oasContents, &urlRewriteOAS))

	extension := urlRewriteOAS.GetTykExtension()
	assert.NotNil(t, extension, "Expected Tyk Extension")
	assert.NotNil(t, extension.Middleware, "Expected middleware")
	assert.NotNil(t, extension.Middleware.Operations, "Expected operations")
	for _, op := range extension.Middleware.Operations {
		assert.NotNil(t, op.URLRewrite, "Expected URLRewrite")
	}

	var native apidef.APIDefinition
	urlRewriteOAS.ExtractTo(&native)

	assert.Len(t, native.VersionData.Versions[oas.Main].ExtendedPaths.URLRewrite, 1)
}

// TestImportValidateRequest
//
// - Loads the complete petstore,
// - Imports the petstore,
// - Asserts expected routes for validateRequest.
func TestImportValidateRequest(t *testing.T) {
	// Load petstore
	oasContents, err := oasTestAPIs.ReadFile("testdata/petstore-no-responses.json")
	assert.NoError(t, err)
	assert.NotNil(t, oasContents)

	// Decode petstore
	var petstore oas.OAS
	assert.NoError(t, json.Unmarshal(oasContents, &petstore))

	// Build tyk extension
	trueVal, falseVal := true, false

	isImport := true
	params := oas.TykExtensionConfigParams{
		ListenPath:      "/listen-api",
		UpstreamURL:     "https://example.org/api",
		ValidateRequest: &trueVal,
		MockResponse:    &falseVal,
	}
	assert.NoError(t, petstore.BuildDefaultTykExtension(params, isImport))

	t.Run("Check paths got imported", func(t *testing.T) {
		assert.Len(t, petstore.Paths.Map(), 13)

		want := []string{
			"/pet/{petId}/uploadImage",
			"/store/inventory",
			"/user",
			"/user/createWithList",
			"/user/login",
			"/pet",
			"/pet/findByStatus",
			"/pet/{petId}",
			"/user/{username}",
			"/user/logout",
			"/pet/findByTags",
			"/store/order",
			"/store/order/{orderId}",
		}

		got := make([]string, 0, len(petstore.Paths.Map()))
		for endpoint := range petstore.Paths.Map() {
			got = append(got, endpoint)
		}

		sort.Strings(want)
		sort.Strings(got)

		assert.Equal(t, want, got)
	})

	t.Run("Check middlware for validateRequest got defined", func(t *testing.T) {
		extension := petstore.GetTykExtension()
		assert.NotNil(t, extension, "Expected Tyk Extension")
		assert.NotNil(t, extension.Middleware, "Expected middleware")
		assert.NotNil(t, extension.Middleware.Operations, "Expected operations")

		want := []string{
			"createUser",
			"createUsersWithListInput",
			"deleteOrder",
			"deletePet",
			"deleteUser",
			"findPetsByStatus",
			"findPetsByTags",
			"getOrderById",
			"getPetById",
			"getUserByName",
			"loginUser",
			"placeOrder",
			"updatePetWithForm",
			"updateUser",
			"uploadFile",
		}

		got := make([]string, 0, len(extension.Middleware.Operations))
		for operationID, op := range extension.Middleware.Operations {
			if op.ValidateRequest != nil {
				got = append(got, operationID)
			}
		}

		sort.Strings(want)
		sort.Strings(got)

		assert.Equal(t, want, got)
	})
}

package oas_test

import (
	"encoding/json"
	"io/ioutil"
	"path"
	"runtime"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

// findTestPath makes tests work with any working dir.
func findTestPath(filename string) string {
	_, testFilename, _, _ := runtime.Caller(0)
	testDir := path.Dir(testFilename)
	return path.Join(testDir, filename)
}

// TestImportValidateRequest
//
// - Loads the complete petstore,
// - Imports the petstore,
// - Asserts expected routes for validateRequest.
func TestImportValidateRequest(t *testing.T) {
	// Load petstore
	oasContents, err := ioutil.ReadFile(findTestPath("testdata/petstore-no-responses.json"))
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
		assert.Len(t, petstore.Paths, 13)

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

		got := make([]string, 0, len(petstore.Paths))
		for endpoint, _ := range petstore.Paths {
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

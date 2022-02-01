package oas

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/stretchr/testify/assert"
)

func TestOperations(t *testing.T) {
	var extended apidef.ExtendedPathsSet
	Fill(t, &extended.WhiteList, 0)
	Fill(t, &extended.BlackList, 0)
	Fill(t, &extended.Ignored, 0)
	Fill(t, &extended.MockResponse, 0)

	sw := &OAS{}
	sw.fillPathsAndOperations(extended)

	var converted apidef.ExtendedPathsSet
	sw.extractPathsAndOperations(&converted)

	assert.Equal(t, extended, converted)
}

func TestAll(t *testing.T) {
	var api apidef.APIDefinition
	Fill(t, &api, 0)
	api.VersionDefinition.Enabled = false
	api.VersionDefinition.Versions = nil
	_, err := api.Migrate()
	assert.NoError(t, err)

	sw := &OAS{}

	sw.Fill(api)

	byt, _ := json.MarshalIndent(sw, "", "  ")
	fmt.Println(string(byt))

	var converted apidef.APIDefinition
	sw.ExtractTo(&converted)

}

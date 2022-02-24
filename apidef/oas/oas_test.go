package oas

import (
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/stretchr/testify/assert"
)

func TestOAS(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		var emptyOAS OAS

		var convertedAPI apidef.APIDefinition
		emptyOAS.ExtractTo(&convertedAPI)

		var resultOAS OAS
		resultOAS.Fill(convertedAPI)

		assert.Equal(t, emptyOAS, resultOAS)
	})

	var api apidef.APIDefinition
	api.AuthConfigs = make(map[string]apidef.AuthConfig)

	a := apidef.AuthConfig{}
	Fill(t, &a, 0)
	api.AuthConfigs[apidef.AuthTokenType] = a

	sw := &OAS{}
	sw.Fill(api)

	var converted apidef.APIDefinition
	sw.ExtractTo(&converted)

	assert.Equal(t, api.AuthConfigs, converted.AuthConfigs)
}

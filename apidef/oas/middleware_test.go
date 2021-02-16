package oas

import (
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/stretchr/testify/assert"
)

func TestGlobal(t *testing.T) {
	var emptyGlobal Global

	var convertedAPI apidef.APIDefinition
	emptyGlobal.ExtractTo(&convertedAPI)

	var resultGlobal Global
	resultGlobal.Fill(convertedAPI)

	assert.Equal(t, emptyGlobal, resultGlobal)
}

func TestCORS(t *testing.T) {
	var emptyCORS CORS

	var convertedCORS apidef.CORSConfig
	emptyCORS.ExtractTo(&convertedCORS)

	var resultCORS CORS
	resultCORS.Fill(convertedCORS)

	assert.Equal(t, emptyCORS, resultCORS)
}

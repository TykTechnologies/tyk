package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadedAPIInfo_TypeAlias(t *testing.T) {
	// Verify the type alias works correctly
	info := LoadedAPIInfo{APIID: "test-api"}
	assert.Equal(t, "test-api", info.APIID)
}

func TestLoadedPolicyInfo_TypeAlias(t *testing.T) {
	info := LoadedPolicyInfo{PolicyID: "test-policy"}
	assert.Equal(t, "test-policy", info.PolicyID)
}

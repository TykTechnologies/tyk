package regression

import (
	"embed"
	"encoding/json"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/gateway"
	"github.com/stretchr/testify/require"
)

var (
	//go:embed testdata/*
	testdata embed.FS
)

func loadAPISpec(tb testing.TB, filename string) *gateway.APISpec {
	tb.Helper()

	data, err := testdata.ReadFile(filename)
	require.NoError(tb, err)

	apidef := &apidef.APIDefinition{}
	err = json.Unmarshal(data, apidef)
	require.NoError(tb, err)

	return &gateway.APISpec{
		APIDefinition: apidef,
	}
}

func loadFile(tb testing.TB, filename string) []byte {
	tb.Helper()

	data, err := testdata.ReadFile(filename)
	require.NoError(tb, err)

	return data
}

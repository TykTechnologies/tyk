package oas

import (
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/stretchr/testify/assert"
)

func TestServer(t *testing.T) {
	var emptyServer Server

	var convertedAPI apidef.APIDefinition
	emptyServer.ExtractTo(&convertedAPI)

	var resultServer Server
	resultServer.Fill(convertedAPI)

	assert.Equal(t, emptyServer, resultServer)
}

func TestListenPath(t *testing.T) {
	var emptyListenPath ListenPath

	var convertedAPI apidef.APIDefinition
	emptyListenPath.ExtractTo(&convertedAPI)

	var resultListenPath ListenPath
	resultListenPath.Fill(convertedAPI)

	assert.Equal(t, emptyListenPath, resultListenPath)
}

func TestClientCertificates(t *testing.T) {
	var emptyClientCertificates ClientCertificates

	var convertedAPI apidef.APIDefinition
	emptyClientCertificates.ExtractTo(&convertedAPI)

	var resultClientCertificates ClientCertificates
	resultClientCertificates.Fill(convertedAPI)

	assert.Equal(t, emptyClientCertificates, resultClientCertificates)
}

func TestPinnedPublicKeys(t *testing.T) {
	var pinnedPublicKeys PinnedPublicKeys
	Fill(t, &pinnedPublicKeys, 0)

	convertedPinnedPublicKeys := make(map[string]string)
	pinnedPublicKeys.ExtractTo(convertedPinnedPublicKeys)

	resultPinnedPublicKeys := make(PinnedPublicKeys, len(pinnedPublicKeys))
	resultPinnedPublicKeys.Fill(convertedPinnedPublicKeys)

	assert.Equal(t, pinnedPublicKeys, resultPinnedPublicKeys)
}

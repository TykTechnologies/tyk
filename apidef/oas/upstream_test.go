package oas

import (
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/stretchr/testify/assert"
)

func TestUpstream(t *testing.T) {
	var emptyUpstream Upstream

	var convertedAPI apidef.APIDefinition
	emptyUpstream.ExtractTo(&convertedAPI)

	var resultUpstream Upstream
	resultUpstream.Fill(convertedAPI)

	assert.Equal(t, emptyUpstream, resultUpstream)
}

func TestServiceDiscovery(t *testing.T) {
	var emptyServiceDiscovery ServiceDiscovery

	var convertedServiceDiscovery apidef.ServiceDiscoveryConfiguration
	emptyServiceDiscovery.ExtractTo(&convertedServiceDiscovery)

	var resultServiceDiscovery ServiceDiscovery
	resultServiceDiscovery.Fill(convertedServiceDiscovery)

	assert.Equal(t, emptyServiceDiscovery, resultServiceDiscovery)
}

func TestTest(t *testing.T) {
	var emptyTest Test

	var convertedTest apidef.UptimeTests
	emptyTest.ExtractTo(&convertedTest)

	var resultTest Test
	resultTest.Fill(convertedTest)

	assert.Equal(t, emptyTest, resultTest)
}

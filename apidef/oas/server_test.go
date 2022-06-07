package oas

import (
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/stretchr/testify/assert"
)

func TestServer(t *testing.T) {
	t.Parallel()

	var emptyServer Server

	var convertedAPI apidef.APIDefinition
	emptyServer.ExtractTo(&convertedAPI)

	var resultServer Server
	resultServer.Fill(convertedAPI)

	assert.Equal(t, emptyServer, resultServer)
}

func TestListenPath(t *testing.T) {
	t.Parallel()

	var emptyListenPath ListenPath

	var convertedAPI apidef.APIDefinition
	emptyListenPath.ExtractTo(&convertedAPI)

	var resultListenPath ListenPath
	resultListenPath.Fill(convertedAPI)

	assert.Equal(t, emptyListenPath, resultListenPath)
}

func TestClientCertificates(t *testing.T) {
	t.Parallel()

	var emptyClientCertificates ClientCertificates

	var convertedAPI apidef.APIDefinition
	emptyClientCertificates.ExtractTo(&convertedAPI)

	var resultClientCertificates ClientCertificates
	resultClientCertificates.Fill(convertedAPI)

	assert.Equal(t, emptyClientCertificates, resultClientCertificates)
}

func TestPinnedPublicKeys(t *testing.T) {
	t.Parallel()

	var pinnedPublicKeys PinnedPublicKeys
	Fill(t, &pinnedPublicKeys, 0)

	convertedPinnedPublicKeys := make(map[string]string)
	pinnedPublicKeys.ExtractTo(convertedPinnedPublicKeys)

	resultPinnedPublicKeys := make(PinnedPublicKeys, len(pinnedPublicKeys))
	resultPinnedPublicKeys.Fill(convertedPinnedPublicKeys)

	assert.Equal(t, pinnedPublicKeys, resultPinnedPublicKeys)
}

func TestTagsImport(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		title         string
		input         *GatewayTags
		expectEnabled bool
		expectValues  []string
	}{
		{
			"keep segment tags values if disabled",
			&GatewayTags{Enabled: false, Tags: []string{"a", "b", "c"}},
			false,
			[]string{"a", "b", "c"},
		},
		{
			"keep segment tags values if enabled",
			&GatewayTags{Enabled: true, Tags: []string{"a", "b", "c"}},
			true,
			[]string{"a", "b", "c"},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()

			var apidef apidef.APIDefinition

			tc.input.ExtractTo(&apidef)

			assert.Equal(t, tc.expectEnabled, apidef.EnableTags)
			assert.Equal(t, tc.expectValues, apidef.Tags)
		})
	}
}
func TestCustomDomain(t *testing.T) {
	t.Run("extractTo api definition", func(t *testing.T) {
		testcases := []struct {
			title       string
			input       Domain
			expectValue apidef.APIDefinition
		}{
			{
				"enabled=false, name=nil",
				Domain{Enabled: false, Name: ""},
				apidef.APIDefinition{},
			},
			{
				"enabled=false, name=(valid-domain)",
				Domain{Enabled: false, Name: "example.com"},
				apidef.APIDefinition{DomainDisabled: true, Domain: "example.com"},
			},
			{
				"enabled=true, name=nil",
				Domain{Enabled: true, Name: ""},
				apidef.APIDefinition{DomainDisabled: false, Domain: ""},
			},
			{
				"enabled=true, name=(valid-domain)",
				Domain{Enabled: true, Name: "example.com"},
				apidef.APIDefinition{DomainDisabled: false, Domain: "example.com"},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.title, func(t *testing.T) {
				var apiDef apidef.APIDefinition

				tc.input.ExtractTo(&apiDef)

				assert.Equal(t, tc.expectValue, apiDef)
			})
		}
	})
	t.Run("fillFrom api definition", func(t *testing.T) {
		testcases := []struct {
			title         string
			input         apidef.APIDefinition
			expectedValue Domain
		}{
			{
				"disabled=false, name=nil",
				apidef.APIDefinition{DomainDisabled: false, Domain: ""},
				Domain{},
			},
			{
				"disabled=false, name=(valid-domain)",
				apidef.APIDefinition{DomainDisabled: false, Domain: "example.com"},
				Domain{Enabled: true, Name: "example.com"},
			},
			{
				"disabled=true, name=nil",
				apidef.APIDefinition{DomainDisabled: true, Domain: ""},
				Domain{Enabled: false, Name: ""},
			},
			{
				"disabled=true, name=(valid-domain)",
				apidef.APIDefinition{DomainDisabled: true, Domain: "example.com"},
				Domain{Enabled: false, Name: "example.com"},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.title, func(t *testing.T) {
				var customDomain Domain

				customDomain.Fill(tc.input)

				assert.Equal(t, tc.expectedValue, customDomain)
			})
		}
	})
}

func TestTagsExportServer(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		title    string
		input    apidef.APIDefinition
		expected *GatewayTags
	}{
		{
			"export segment tags if enabled",
			apidef.APIDefinition{
				EnableTags: true,
				Tags:       []string{"a", "b", "c"},
			},
			&GatewayTags{
				Enabled: true,
				Tags:    []string{"a", "b", "c"},
			},
		},
		{
			"export segment tags if disabled",
			apidef.APIDefinition{
				EnableTags: true,
				Tags:       []string{"a", "b", "c"},
			},
			&GatewayTags{
				Enabled: false,
				Tags:    []string{"a", "b", "c"},
			},
		},
		{
			"empty segment tags",
			apidef.APIDefinition{},
			nil,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()

			server := new(Server)
			server.Fill(tc.input)

			assert.Equal(t, tc.expected, server.GatewayTags)
		})
	}
}

package oas

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
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

func TestGatewayTags(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		input GatewayTags
		want  GatewayTags
		omit  bool
	}{
		{
			input: GatewayTags{},
			want:  GatewayTags{Tags: []string{}},
			omit:  true,
		},
		{
			input: GatewayTags{Enabled: true},
			want:  GatewayTags{Enabled: true, Tags: []string{}},
		},
		{
			input: GatewayTags{Enabled: true, Tags: []string{}},
			want:  GatewayTags{Enabled: true, Tags: []string{}},
		},
		{
			input: GatewayTags{Enabled: true, Tags: []string{"test"}},
			want:  GatewayTags{Enabled: true, Tags: []string{"test"}},
		},
		{
			input: GatewayTags{Enabled: true, Tags: []string{"t1", "t2"}},
			want:  GatewayTags{Enabled: true, Tags: []string{"t1", "t2"}},
		},
		{
			input: GatewayTags{Enabled: false, Tags: []string{"t1", "t2"}},
			want:  GatewayTags{Enabled: false, Tags: []string{"t1", "t2"}},
		},
	}

	t.Run("Fill GatewayTags from APIDef", func(t *testing.T) {
		// We currently don't match APIDef direct fill with OAS
		t.Skip() // TODO: TT-5720

		t.Parallel()

		for idx, tc := range testcases {
			var api apidef.APIDefinition
			tc.input.ExtractTo(&api)

			got := new(GatewayTags)
			got.Fill(api)

			assert.Equal(t, tc.want, *got, fmt.Sprintf("Test case %d", idx))
		}
	})

	t.Run("Fill OAS GatewayTags from APIDef", func(t *testing.T) {
		t.Parallel()

		for idx, tc := range testcases {
			var api apidef.APIDefinition
			tc.input.ExtractTo(&api)

			var oas OAS
			oas.Fill(api)

			var schema = oas.GetTykExtension()
			var got = schema.Server.GatewayTags

			if tc.omit {
				assert.Nil(t, got, idx)
			} else {
				assert.Equal(t, tc.want, *got, fmt.Sprintf("Test case %d", idx))
			}
		}
	})
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
				TagsDisabled: false,
				Tags:         []string{"a", "b", "c"},
			},
			&GatewayTags{
				Enabled: true,
				Tags:    []string{"a", "b", "c"},
			},
		},
		{
			"export segment tags if disabled",
			apidef.APIDefinition{
				TagsDisabled: true,
				Tags:         []string{"a", "b", "c"},
			},
			&GatewayTags{
				Enabled: false,
				Tags:    []string{"a", "b", "c"},
			},
		},
		{
			"empty segment tags",
			apidef.APIDefinition{},
			&GatewayTags{
				Enabled: true,
				Tags:    []string{},
			},
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

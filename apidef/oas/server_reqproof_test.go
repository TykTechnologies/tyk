package oas

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

// Verifies: SYS-REQ-104, SW-REQ-062
// SW-REQ-062:nominal:nominal
// SW-REQ-062:boundary:nominal
// SW-REQ-062:determinism:nominal
func TestServerProjectionPreservesClassicModelShape(t *testing.T) {
	t.Run("aggregate fill and extract preserve server classic fields", func(t *testing.T) {
		api := apidef.APIDefinition{
			Protocol:                  "http2",
			ListenPort:                9443,
			UseMutualTLSAuth:          true,
			ClientCertificates:        []string{"client-cert-a", "client-cert-b"},
			TagsDisabled:              false,
			Tags:                      []string{"edge", "prod"},
			DomainDisabled:            false,
			Domain:                    "api.example.com",
			Certificates:              []string{"domain-cert-a"},
			EnableDetailedRecording:   true,
			DetailedTracing:           true,
			IPAccessControlDisabled:   false,
			AllowedIPs:                []string{"192.0.2.0/24"},
			BlacklistedIPs:            []string{"198.51.100.1"},
			EnableBatchRequestSupport: true,
			Proxy: apidef.ProxyConfig{
				ListenPath:      "/pets/",
				StripListenPath: true,
			},
		}

		var server Server
		server.Fill(api)

		assert.Equal(t, "http2", server.Protocol)
		assert.Equal(t, 9443, server.Port)
		assert.Equal(t, ListenPath{Value: "/pets/", Strip: true}, server.ListenPath)
		require.NotNil(t, server.ClientCertificates)
		assert.Equal(t, ClientCertificates{Enabled: true, Allowlist: []string{"client-cert-a", "client-cert-b"}}, *server.ClientCertificates)
		require.NotNil(t, server.GatewayTags)
		assert.Equal(t, GatewayTags{Enabled: true, Tags: []string{"edge", "prod"}}, *server.GatewayTags)
		require.NotNil(t, server.CustomDomain)
		assert.Equal(t, Domain{Enabled: true, Name: "api.example.com", Certificates: []string{"domain-cert-a"}}, *server.CustomDomain)
		require.NotNil(t, server.DetailedActivityLogs)
		assert.Equal(t, DetailedActivityLogs{Enabled: true}, *server.DetailedActivityLogs)
		require.NotNil(t, server.DetailedTracing)
		assert.Equal(t, DetailedTracing{Enabled: true}, *server.DetailedTracing)
		require.NotNil(t, server.IPAccessControl)
		assert.Equal(t, IPAccessControl{Enabled: true, Allow: []string{"192.0.2.0/24"}, Block: []string{"198.51.100.1"}}, *server.IPAccessControl)
		require.NotNil(t, server.BatchProcessing)
		assert.Equal(t, BatchProcessing{Enabled: true}, *server.BatchProcessing)

		var extracted apidef.APIDefinition
		server.ExtractTo(&extracted)

		assert.Equal(t, api.Protocol, extracted.Protocol)
		assert.Equal(t, api.ListenPort, extracted.ListenPort)
		assert.Equal(t, api.Proxy.ListenPath, extracted.Proxy.ListenPath)
		assert.Equal(t, api.Proxy.StripListenPath, extracted.Proxy.StripListenPath)
		assert.Equal(t, api.UseMutualTLSAuth, extracted.UseMutualTLSAuth)
		assert.Equal(t, api.ClientCertificates, extracted.ClientCertificates)
		assert.Equal(t, api.TagsDisabled, extracted.TagsDisabled)
		assert.Equal(t, api.Tags, extracted.Tags)
		assert.Equal(t, api.DomainDisabled, extracted.DomainDisabled)
		assert.Equal(t, api.Domain, extracted.Domain)
		assert.Equal(t, api.Certificates, extracted.Certificates)
		assert.Equal(t, api.EnableDetailedRecording, extracted.EnableDetailedRecording)
		assert.Equal(t, api.DetailedTracing, extracted.DetailedTracing)
		assert.Equal(t, api.IPAccessControlDisabled, extracted.IPAccessControlDisabled)
		assert.Equal(t, api.AllowedIPs, extracted.AllowedIPs)
		assert.Equal(t, api.BlacklistedIPs, extracted.BlacklistedIPs)
		assert.Equal(t, api.EnableBatchRequestSupport, extracted.EnableBatchRequestSupport)
	})

	t.Run("default inversion children are preserved while zero optional children are omitted", func(t *testing.T) {
		var server Server
		server.Fill(apidef.APIDefinition{})

		assert.Nil(t, server.ClientCertificates)
		assert.Nil(t, server.DetailedActivityLogs)
		assert.Nil(t, server.DetailedTracing)
		assert.Nil(t, server.EventHandlers)
		assert.Nil(t, server.BatchProcessing)
		require.NotNil(t, server.GatewayTags)
		assert.Equal(t, GatewayTags{Enabled: true}, *server.GatewayTags)
		require.NotNil(t, server.CustomDomain)
		assert.Equal(t, Domain{Enabled: true}, *server.CustomDomain)
		require.NotNil(t, server.IPAccessControl)
		assert.Equal(t, IPAccessControl{Enabled: true}, *server.IPAccessControl)

		server = Server{ListenPath: ListenPath{Value: "/minimal"}}
		var extracted apidef.APIDefinition
		server.ExtractTo(&extracted)

		assert.Nil(t, server.ClientCertificates)
		assert.Nil(t, server.GatewayTags)
		assert.Nil(t, server.CustomDomain)
		assert.Nil(t, server.DetailedActivityLogs)
		assert.Nil(t, server.DetailedTracing)
		assert.Nil(t, server.EventHandlers)
		assert.Nil(t, server.IPAccessControl)
		assert.Nil(t, server.BatchProcessing)
		assert.Equal(t, "/minimal", extracted.Proxy.ListenPath)
		assert.True(t, extracted.TagsDisabled)
		assert.True(t, extracted.DomainDisabled)
		assert.True(t, extracted.IPAccessControlDisabled)
		assert.False(t, extracted.EnableBatchRequestSupport)
	})

	t.Run("leaf mappers preserve boundary inversions and zero values", func(t *testing.T) {
		var api apidef.APIDefinition
		listenPathInput := ListenPath{Value: "/", Strip: false}
		certificatesInput := ClientCertificates{Enabled: false, Allowlist: []string{}}
		tagsInput := GatewayTags{Enabled: false, Tags: []string{"disabled-tag"}}
		domainInput := Domain{Enabled: false, Name: "disabled.example.com", Certificates: []string{"cert-disabled"}}
		activityLogsInput := DetailedActivityLogs{Enabled: false}
		tracingInput := DetailedTracing{Enabled: false}
		ipAccessInput := IPAccessControl{Enabled: false, Allow: []string{"203.0.113.10"}, Block: []string{"203.0.113.11"}}
		batchInput := BatchProcessing{Enabled: false}
		listenPathInput.ExtractTo(&api)
		certificatesInput.ExtractTo(&api)
		tagsInput.ExtractTo(&api)
		domainInput.ExtractTo(&api)
		activityLogsInput.ExtractTo(&api)
		tracingInput.ExtractTo(&api)
		ipAccessInput.ExtractTo(&api)
		batchInput.ExtractTo(&api)

		assert.Equal(t, "/", api.Proxy.ListenPath)
		assert.False(t, api.Proxy.StripListenPath)
		assert.False(t, api.UseMutualTLSAuth)
		assert.Empty(t, api.ClientCertificates)
		assert.True(t, api.TagsDisabled)
		assert.Equal(t, []string{"disabled-tag"}, api.Tags)
		assert.True(t, api.DomainDisabled)
		assert.Equal(t, "disabled.example.com", api.Domain)
		assert.Equal(t, []string{"cert-disabled"}, api.Certificates)
		assert.False(t, api.EnableDetailedRecording)
		assert.False(t, api.DetailedTracing)
		assert.True(t, api.IPAccessControlDisabled)
		assert.Equal(t, []string{"203.0.113.10"}, api.AllowedIPs)
		assert.Equal(t, []string{"203.0.113.11"}, api.BlacklistedIPs)
		assert.False(t, api.EnableBatchRequestSupport)

		var listenPath ListenPath
		var certificates ClientCertificates
		var tags GatewayTags
		var domain Domain
		var activityLogs DetailedActivityLogs
		var tracing DetailedTracing
		var ipAccess IPAccessControl
		var batch BatchProcessing
		listenPath.Fill(api)
		certificates.Fill(api)
		tags.Fill(api)
		domain.Fill(api)
		activityLogs.Fill(api)
		tracing.Fill(api)
		ipAccess.Fill(api)
		batch.Fill(api)

		assert.Equal(t, ListenPath{Value: "/"}, listenPath)
		assert.Equal(t, ClientCertificates{Allowlist: []string{}}, certificates)
		assert.Equal(t, GatewayTags{Enabled: false, Tags: []string{"disabled-tag"}}, tags)
		assert.Equal(t, Domain{Enabled: false, Name: "disabled.example.com", Certificates: []string{"cert-disabled"}}, domain)
		assert.Equal(t, DetailedActivityLogs{}, activityLogs)
		assert.Equal(t, DetailedTracing{}, tracing)
		assert.Equal(t, IPAccessControl{Enabled: false, Allow: []string{"203.0.113.10"}, Block: []string{"203.0.113.11"}}, ipAccess)
		assert.Equal(t, BatchProcessing{}, batch)
	})

	t.Run("repeated projection is deterministic", func(t *testing.T) {
		api := apidef.APIDefinition{
			Protocol:                  "h2c",
			ListenPort:                8081,
			UseMutualTLSAuth:          true,
			ClientCertificates:        []string{"client-cert-a"},
			Tags:                      []string{"prod"},
			Domain:                    "repeat.example.com",
			Certificates:              []string{"domain-cert-a"},
			EnableDetailedRecording:   true,
			DetailedTracing:           true,
			AllowedIPs:                []string{"192.0.2.1"},
			EnableBatchRequestSupport: true,
			Proxy: apidef.ProxyConfig{
				ListenPath:      "/repeat",
				StripListenPath: true,
			},
		}

		var first Server
		var second Server
		first.Fill(api)
		second.Fill(api)
		assert.Equal(t, first, second)

		var firstExtracted apidef.APIDefinition
		var secondExtracted apidef.APIDefinition
		first.ExtractTo(&firstExtracted)
		second.ExtractTo(&secondExtracted)
		assert.Equal(t, firstExtracted, secondExtracted)
	})
}

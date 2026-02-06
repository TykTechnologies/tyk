package gateway

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
)

// Helper function to create test API spec
func createTestAPISpec(apiID string, certs, clientCerts []string, upstreamCerts, pinnedKeys map[string]string) *APISpec {
	return &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:                apiID,
			Certificates:         certs,
			ClientCertificates:   clientCerts,
			UpstreamCertificates: upstreamCerts,
			PinnedPublicKeys:     pinnedKeys,
		},
	}
}

func TestNewUsageTracker(t *testing.T) {
	cr := newUsageTracker()

	assert.NotNil(t, cr)
	assert.NotNil(t, cr.apis)
	assert.Equal(t, 0, cr.Len())
}

func TestCollectCertUsageMap(t *testing.T) {
	t.Run("empty specs and no server certs", func(t *testing.T) {
		usageMap := CollectCertUsageMap(nil, nil)

		assert.NotNil(t, usageMap)
		assert.Empty(t, usageMap)
	})

	t.Run("only server certs, no API specs", func(t *testing.T) {
		serverCerts := []string{"server-cert1", "server-cert2"}
		usageMap := CollectCertUsageMap(nil, serverCerts)

		assert.Len(t, usageMap, 2)
		assert.Contains(t, usageMap, "server-cert1")
		assert.Contains(t, usageMap, "server-cert2")

		// Server certs should be associated with __server__
		assert.Contains(t, usageMap["server-cert1"], "__server__")
		assert.Contains(t, usageMap["server-cert2"], "__server__")
	})

	t.Run("only API specs, no server certs", func(t *testing.T) {
		specs := []*APISpec{
			createTestAPISpec("api1", []string{"cert1", "cert2"}, nil, nil, nil),
			createTestAPISpec("api2", []string{"cert3"}, nil, nil, nil),
		}
		usageMap := CollectCertUsageMap(specs, nil)

		assert.Len(t, usageMap, 3)
		assert.Contains(t, usageMap, "cert1")
		assert.Contains(t, usageMap, "cert2")
		assert.Contains(t, usageMap, "cert3")

		// Verify API associations
		assert.Contains(t, usageMap["cert1"], "api1")
		assert.Contains(t, usageMap["cert2"], "api1")
		assert.Contains(t, usageMap["cert3"], "api2")
	})

	t.Run("both server certs and API specs", func(t *testing.T) {
		specs := []*APISpec{
			createTestAPISpec("api1", []string{"cert1"}, nil, nil, nil),
		}
		serverCerts := []string{"server-cert1"}
		usageMap := CollectCertUsageMap(specs, serverCerts)

		assert.Len(t, usageMap, 2)
		assert.Contains(t, usageMap, "cert1")
		assert.Contains(t, usageMap, "server-cert1")

		assert.Contains(t, usageMap["cert1"], "api1")
		assert.Contains(t, usageMap["server-cert1"], "__server__")
	})

	t.Run("multiple APIs using the same certificate", func(t *testing.T) {
		specs := []*APISpec{
			createTestAPISpec("api1", []string{"shared-cert"}, nil, nil, nil),
			createTestAPISpec("api2", []string{"shared-cert"}, nil, nil, nil),
			createTestAPISpec("api3", []string{"shared-cert", "cert3"}, nil, nil, nil),
		}
		usageMap := CollectCertUsageMap(specs, nil)

		assert.Len(t, usageMap, 2)
		assert.Contains(t, usageMap, "shared-cert")
		assert.Contains(t, usageMap, "cert3")

		// shared-cert should be associated with all three APIs
		assert.Len(t, usageMap["shared-cert"], 3)
		assert.Contains(t, usageMap["shared-cert"], "api1")
		assert.Contains(t, usageMap["shared-cert"], "api2")
		assert.Contains(t, usageMap["shared-cert"], "api3")

		// cert3 only associated with api3
		assert.Len(t, usageMap["cert3"], 1)
		assert.Contains(t, usageMap["cert3"], "api3")
	})

	t.Run("API with multiple certificate types", func(t *testing.T) {
		specs := []*APISpec{
			createTestAPISpec("api1",
				[]string{"cert1"},
				[]string{"cert2"},
				map[string]string{"upstream": "cert3"},
				map[string]string{"pinned": "cert4"}),
		}
		usageMap := CollectCertUsageMap(specs, nil)

		assert.Len(t, usageMap, 4)
		assert.Contains(t, usageMap, "cert1")
		assert.Contains(t, usageMap, "cert2")
		assert.Contains(t, usageMap, "cert3")
		assert.Contains(t, usageMap, "cert4")

		// All certs associated with api1
		assert.Contains(t, usageMap["cert1"], "api1")
		assert.Contains(t, usageMap["cert2"], "api1")
		assert.Contains(t, usageMap["cert3"], "api1")
		assert.Contains(t, usageMap["cert4"], "api1")
	})

	t.Run("empty certificate IDs are ignored", func(t *testing.T) {
		specs := []*APISpec{
			createTestAPISpec("api1", []string{"cert1", "", "cert2"}, nil, nil, nil),
		}
		serverCerts := []string{"server-cert1", "", "server-cert2"}
		usageMap := CollectCertUsageMap(specs, serverCerts)

		assert.Len(t, usageMap, 4)
		assert.Contains(t, usageMap, "cert1")
		assert.Contains(t, usageMap, "cert2")
		assert.Contains(t, usageMap, "server-cert1")
		assert.Contains(t, usageMap, "server-cert2")
	})

	t.Run("duplicate certificates within same API are deduplicated", func(t *testing.T) {
		specs := []*APISpec{
			createTestAPISpec("api1",
				[]string{"cert1"},
				[]string{"cert1"}, // duplicate
				map[string]string{"upstream": "cert2"},
				nil),
		}
		usageMap := CollectCertUsageMap(specs, nil)

		assert.Len(t, usageMap, 2)
		assert.Contains(t, usageMap, "cert1")
		assert.Contains(t, usageMap, "cert2")

		// cert1 should only be listed once for api1
		assert.Len(t, usageMap["cert1"], 1)
		assert.Contains(t, usageMap["cert1"], "api1")
	})

	t.Run("server cert also used by API", func(t *testing.T) {
		specs := []*APISpec{
			createTestAPISpec("api1", []string{"shared-cert"}, nil, nil, nil),
		}
		serverCerts := []string{"shared-cert"}
		usageMap := CollectCertUsageMap(specs, serverCerts)

		assert.Len(t, usageMap, 1)
		assert.Contains(t, usageMap, "shared-cert")

		// shared-cert should be associated with both __server__ and api1
		assert.Len(t, usageMap["shared-cert"], 2)
		assert.Contains(t, usageMap["shared-cert"], "__server__")
		assert.Contains(t, usageMap["shared-cert"], "api1")
	})
}

func TestUsageTracker_ReplaceAll(t *testing.T) {
	t.Run("replace empty map with populated map", func(t *testing.T) {
		cr := newUsageTracker()

		// Start with empty tracker
		assert.Equal(t, 0, cr.Len())

		// Create new usage map
		newMap := map[string]map[string]struct{}{
			"cert1": {"api1": {}},
			"cert2": {"api2": {}},
		}

		cr.ReplaceAll(newMap)

		assert.Equal(t, 2, cr.Len())
		assert.True(t, cr.Required("cert1"))
		assert.True(t, cr.Required("cert2"))
		assert.Contains(t, cr.APIs("cert1"), "api1")
		assert.Contains(t, cr.APIs("cert2"), "api2")
	})

	t.Run("concurrent reads during replace", func(t *testing.T) {
		cr := newUsageTracker()

		// Start with initial data
		initialMap := map[string]map[string]struct{}{
			"cert1": {"api1": {}},
			"cert2": {"api2": {}},
		}
		cr.ReplaceAll(initialMap)

		var wg sync.WaitGroup

		// Concurrent readers
		wg.Add(50)
		for i := 0; i < 50; i++ {
			go func() {
				defer wg.Done()
				// These reads should not panic and should return consistent results
				cr.Required("cert1")
				cr.Required("cert2")
				cr.APIs("cert1")
				cr.Len()
				cr.Certs()
			}()
		}

		// Concurrent replace
		wg.Add(1)
		go func() {
			defer wg.Done()
			newMap := map[string]map[string]struct{}{
				"cert3": {"api3": {}},
				"cert4": {"api4": {}},
			}
			cr.ReplaceAll(newMap)
		}()

		wg.Wait()

		// After replacement, new data should be present
		assert.True(t, cr.Required("cert3"))
		assert.True(t, cr.Required("cert4"))
		assert.Equal(t, 2, cr.Len())
	})

	t.Run("multiple concurrent replaces", func(t *testing.T) {
		cr := newUsageTracker()

		var wg sync.WaitGroup

		// Multiple concurrent replaces
		wg.Add(10)
		for i := 0; i < 10; i++ {
			go func(num int) {
				defer wg.Done()
				newMap := map[string]map[string]struct{}{
					"cert-" + string(rune(num)): {"api-" + string(rune(num)): {}},
				}
				cr.ReplaceAll(newMap)
			}(i)
		}

		wg.Wait()

		// Final state should be consistent (one of the replacements won)
		length := cr.Len()
		assert.Equal(t, 1, length)
	})

}

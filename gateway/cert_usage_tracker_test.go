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

func TestUsageTracker_Register(t *testing.T) {
	t.Run("single API with single certificate type", func(t *testing.T) {
		cr := newUsageTracker()
		spec := createTestAPISpec("api1", []string{"cert1", "cert2"}, nil, nil, nil)

		cr.Register(spec)

		assert.True(t, cr.Required("cert1"))
		assert.True(t, cr.Required("cert2"))
		assert.False(t, cr.Required("cert3"))
		assert.Equal(t, 2, cr.Len())
	})

	t.Run("single API with multiple certificate types", func(t *testing.T) {
		cr := newUsageTracker()
		spec := createTestAPISpec("api1",
			[]string{"cert1"},
			[]string{"cert2"},
			map[string]string{"upstream": "cert3"},
			map[string]string{"pinned": "cert4"})

		cr.Register(spec)

		assert.True(t, cr.Required("cert1"))
		assert.True(t, cr.Required("cert2"))
		assert.True(t, cr.Required("cert3"))
		assert.True(t, cr.Required("cert4"))
		assert.Equal(t, 4, cr.Len())
	})

	t.Run("multiple APIs sharing same certificate", func(t *testing.T) {
		cr := newUsageTracker()

		spec1 := createTestAPISpec("api1", []string{"cert1", "shared-cert"}, nil, nil, nil)
		spec2 := createTestAPISpec("api2", []string{"cert2", "shared-cert"}, nil, nil, nil)

		cr.Register(spec1)
		cr.Register(spec2)

		assert.True(t, cr.Required("cert1"))
		assert.True(t, cr.Required("cert2"))
		assert.True(t, cr.Required("shared-cert"))
		assert.Equal(t, 3, cr.Len())

		// Check that shared-cert is associated with both APIs
		apis := cr.APIs("shared-cert")
		assert.Len(t, apis, 2)
		assert.Contains(t, apis, "api1")
		assert.Contains(t, apis, "api2")
	})

	t.Run("empty certificate IDs are ignored", func(t *testing.T) {
		cr := newUsageTracker()
		spec := createTestAPISpec("api1", []string{"cert1", "", "cert2"}, nil, nil, nil)

		cr.Register(spec)

		assert.True(t, cr.Required("cert1"))
		assert.True(t, cr.Required("cert2"))
		assert.Equal(t, 2, cr.Len())
	})

	t.Run("duplicate certificates within same API are deduplicated", func(t *testing.T) {
		cr := newUsageTracker()
		spec := createTestAPISpec("api1",
			[]string{"cert1"},
			[]string{"cert1"}, // duplicate
			map[string]string{"upstream": "cert2"},
			nil)

		cr.Register(spec)

		assert.True(t, cr.Required("cert1"))
		assert.True(t, cr.Required("cert2"))
		assert.Equal(t, 2, cr.Len())
	})
}

func TestUsageTracker_RegisterServerCerts(t *testing.T) {
	t.Run("register server certificates", func(t *testing.T) {
		cr := newUsageTracker()

		cr.RegisterServerCerts([]string{"server-cert1", "server-cert2"})

		assert.True(t, cr.Required("server-cert1"))
		assert.True(t, cr.Required("server-cert2"))
		assert.Equal(t, 2, cr.Len())

		// Check that server certs are associated with __server__
		apis := cr.APIs("server-cert1")
		assert.Len(t, apis, 1)
		assert.Contains(t, apis, "__server__")
	})

	t.Run("empty certificate IDs are ignored", func(t *testing.T) {
		cr := newUsageTracker()

		cr.RegisterServerCerts([]string{"server-cert1", "", "server-cert2"})

		assert.True(t, cr.Required("server-cert1"))
		assert.True(t, cr.Required("server-cert2"))
		assert.Equal(t, 2, cr.Len())
	})

	t.Run("server certs combined with API certs", func(t *testing.T) {
		cr := newUsageTracker()

		spec := createTestAPISpec("api1", []string{"cert1"}, nil, nil, nil)
		cr.Register(spec)
		cr.RegisterServerCerts([]string{"server-cert1"})

		assert.True(t, cr.Required("cert1"))
		assert.True(t, cr.Required("server-cert1"))
		assert.Equal(t, 2, cr.Len())

		// cert1 should be associated with api1
		apis := cr.APIs("cert1")
		assert.Len(t, apis, 1)
		assert.Contains(t, apis, "api1")

		// server-cert1 should be associated with __server__
		apis = cr.APIs("server-cert1")
		assert.Len(t, apis, 1)
		assert.Contains(t, apis, "__server__")
	})
}

func TestUsageTracker_Required(t *testing.T) {
	t.Run("required certificate", func(t *testing.T) {
		cr := newUsageTracker()
		spec := createTestAPISpec("api1", []string{"cert1"}, nil, nil, nil)
		cr.Register(spec)

		assert.True(t, cr.Required("cert1"))
	})

	t.Run("non-existent certificate", func(t *testing.T) {
		cr := newUsageTracker()

		assert.False(t, cr.Required("non-existent"))
	})

	t.Run("certificate after reset", func(t *testing.T) {
		cr := newUsageTracker()
		spec := createTestAPISpec("api1", []string{"cert1"}, nil, nil, nil)
		cr.Register(spec)
		cr.Reset()

		assert.False(t, cr.Required("cert1"))
	})
}

func TestUsageTracker_APIs(t *testing.T) {
	t.Run("certificate used by single API", func(t *testing.T) {
		cr := newUsageTracker()
		spec := createTestAPISpec("api1", []string{"cert1"}, nil, nil, nil)
		cr.Register(spec)

		apis := cr.APIs("cert1")
		assert.Len(t, apis, 1)
		assert.Contains(t, apis, "api1")
	})

	t.Run("certificate used by multiple APIs", func(t *testing.T) {
		cr := newUsageTracker()

		spec1 := createTestAPISpec("api1", []string{"shared-cert"}, nil, nil, nil)
		spec2 := createTestAPISpec("api2", []string{"shared-cert"}, nil, nil, nil)
		spec3 := createTestAPISpec("api3", []string{"shared-cert"}, nil, nil, nil)

		cr.Register(spec1)
		cr.Register(spec2)
		cr.Register(spec3)

		apis := cr.APIs("shared-cert")
		assert.Len(t, apis, 3)
		assert.Contains(t, apis, "api1")
		assert.Contains(t, apis, "api2")
		assert.Contains(t, apis, "api3")
	})

	t.Run("non-existent certificate", func(t *testing.T) {
		cr := newUsageTracker()

		apis := cr.APIs("non-existent")
		assert.Nil(t, apis)
	})

	t.Run("certificate after reset", func(t *testing.T) {
		cr := newUsageTracker()
		spec := createTestAPISpec("api1", []string{"cert1"}, nil, nil, nil)
		cr.Register(spec)
		cr.Reset()

		apis := cr.APIs("cert1")
		assert.Nil(t, apis)
	})
}

func TestUsageTracker_Reset(t *testing.T) {
	t.Run("reset clears all data", func(t *testing.T) {
		cr := newUsageTracker()

		spec := createTestAPISpec("api1",
			[]string{"cert1"},
			[]string{"cert2"},
			map[string]string{"upstream": "cert3"},
			nil)
		cr.Register(spec)
		cr.RegisterServerCerts([]string{"server-cert1"})

		assert.Equal(t, 4, cr.Len())

		cr.Reset()

		assert.Equal(t, 0, cr.Len())
		assert.False(t, cr.Required("cert1"))
		assert.False(t, cr.Required("cert2"))
		assert.False(t, cr.Required("cert3"))
		assert.False(t, cr.Required("server-cert1"))
		assert.Nil(t, cr.APIs("cert1"))
	})

	t.Run("reset on empty registry", func(t *testing.T) {
		cr := newUsageTracker()

		cr.Reset()

		assert.Equal(t, 0, cr.Len())
	})

	t.Run("register after reset", func(t *testing.T) {
		cr := newUsageTracker()

		spec1 := createTestAPISpec("api1", []string{"cert1"}, nil, nil, nil)
		cr.Register(spec1)
		cr.Reset()

		spec2 := createTestAPISpec("api2", []string{"cert2"}, nil, nil, nil)
		cr.Register(spec2)

		assert.Equal(t, 1, cr.Len())
		assert.False(t, cr.Required("cert1"))
		assert.True(t, cr.Required("cert2"))
	})
}

func TestUsageTracker_Len(t *testing.T) {
	t.Run("length reflects unique certificates", func(t *testing.T) {
		cr := newUsageTracker()

		assert.Equal(t, 0, cr.Len())

		spec1 := createTestAPISpec("api1", []string{"cert1", "cert2"}, nil, nil, nil)
		cr.Register(spec1)
		assert.Equal(t, 2, cr.Len())

		spec2 := createTestAPISpec("api2", []string{"cert2", "cert3"}, nil, nil, nil) // cert2 shared
		cr.Register(spec2)
		assert.Equal(t, 3, cr.Len())

		cr.Reset()
		assert.Equal(t, 0, cr.Len())
	})
}

func TestUsageTracker_Certs(t *testing.T) {
	t.Run("get all certificate IDs", func(t *testing.T) {
		cr := newUsageTracker()

		spec := createTestAPISpec("api1",
			[]string{"cert1"},
			[]string{"cert2"},
			map[string]string{"upstream": "cert3"},
			nil)
		cr.Register(spec)

		certs := cr.Certs()
		assert.Len(t, certs, 3)
		assert.Contains(t, certs, "cert1")
		assert.Contains(t, certs, "cert2")
		assert.Contains(t, certs, "cert3")
	})

	t.Run("empty registry", func(t *testing.T) {
		cr := newUsageTracker()

		certs := cr.Certs()
		assert.Empty(t, certs)
	})

	t.Run("after reset", func(t *testing.T) {
		cr := newUsageTracker()

		spec := createTestAPISpec("api1", []string{"cert1"}, nil, nil, nil)
		cr.Register(spec)
		cr.Reset()

		certs := cr.Certs()
		assert.Empty(t, certs)
	})
}

func TestUsageTracker_ConcurrentAccess(t *testing.T) {
	t.Run("concurrent registration", func(t *testing.T) {
		cr := newUsageTracker()
		var wg sync.WaitGroup

		// Register 100 APIs concurrently
		numAPIs := 100
		wg.Add(numAPIs)
		for i := 0; i < numAPIs; i++ {
			go func(apiNum int) {
				defer wg.Done()
				spec := createTestAPISpec("api-"+string(rune(apiNum)), []string{"cert-" + string(rune(apiNum))}, nil, nil, nil)
				cr.Register(spec)
			}(i)
		}

		wg.Wait()

		assert.Equal(t, numAPIs, cr.Len())
	})

	t.Run("concurrent reads and writes", func(t *testing.T) {
		cr := newUsageTracker()
		var wg sync.WaitGroup

		// Pre-register some certificates
		for i := 0; i < 10; i++ {
			spec := createTestAPISpec("api-"+string(rune(i)), []string{"cert-" + string(rune(i))}, nil, nil, nil)
			cr.Register(spec)
		}

		// Concurrent readers
		wg.Add(50)
		for i := 0; i < 50; i++ {
			go func(num int) {
				defer wg.Done()
				certID := "cert-" + string(rune(num%10))
				cr.Required(certID)
				cr.APIs(certID)
				cr.Len()
				cr.Certs()
			}(i)
		}

		// Concurrent writers
		wg.Add(50)
		for i := 10; i < 60; i++ {
			go func(apiNum int) {
				defer wg.Done()
				spec := createTestAPISpec("api-"+string(rune(apiNum)), []string{"cert-" + string(rune(apiNum))}, nil, nil, nil)
				cr.Register(spec)
			}(i)
		}

		wg.Wait()

		// Should have at least the initial 10 certs
		assert.GreaterOrEqual(t, cr.Len(), 10)
	})

	t.Run("concurrent reset and register", func(t *testing.T) {
		cr := newUsageTracker()
		var wg sync.WaitGroup

		// Pre-register some certificates
		spec := createTestAPISpec("api1", []string{"cert1"}, nil, nil, nil)
		cr.Register(spec)

		// Concurrent resets
		wg.Add(10)
		for i := 0; i < 10; i++ {
			go func() {
				defer wg.Done()
				cr.Reset()
			}()
		}

		// Concurrent registrations
		wg.Add(10)
		for i := 0; i < 10; i++ {
			go func(apiNum int) {
				defer wg.Done()
				spec := createTestAPISpec("api-"+string(rune(apiNum)), []string{"cert-" + string(rune(apiNum))}, nil, nil, nil)
				cr.Register(spec)
			}(i)
		}

		wg.Wait()

		// Final state should be consistent
		length := cr.Len()
		assert.GreaterOrEqual(t, length, 0)
		assert.LessOrEqual(t, length, 10)
	})
}

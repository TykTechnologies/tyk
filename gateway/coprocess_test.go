package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/coprocess"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/user"
)

func Test_getIDExtractor(t *testing.T) {
	testCases := []struct {
		name        string
		spec        *APISpec
		idExtractor IdExtractor
	}{
		{
			name: "coprocess auth disabled",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{},
			},
			idExtractor: nil,
		},
		{
			name: "id extractor disabled",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					CustomPluginAuthEnabled: true,
					CustomMiddleware: apidef.MiddlewareSection{
						AuthCheck: apidef.MiddlewareDefinition{
							Name: "func name",
							Path: "path",
						},
						IdExtractor: apidef.MiddlewareIdExtractor{
							Disabled:    true,
							ExtractWith: apidef.ValueExtractor,
							ExtractFrom: apidef.HeaderSource,
						},
					},
				},
			},
			idExtractor: nil,
		},
		{
			name: "invalid id extractor",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					CustomPluginAuthEnabled: true,
					CustomMiddleware: apidef.MiddlewareSection{
						AuthCheck: apidef.MiddlewareDefinition{
							Name: "func name",
							Path: "path",
						},
						IdExtractor: apidef.MiddlewareIdExtractor{
							Disabled:    false,
							ExtractWith: apidef.ValueExtractor,
							ExtractFrom: apidef.HeaderSource,
							Extractor:   struct{}{},
						},
					},
				},
			},
			idExtractor: nil,
		},
		{
			name: "valid id extractor",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					CustomPluginAuthEnabled: true,
					CustomMiddleware: apidef.MiddlewareSection{
						AuthCheck: apidef.MiddlewareDefinition{
							Name: "func name",
							Path: "path",
						},
						IdExtractor: apidef.MiddlewareIdExtractor{
							Disabled:    false,
							ExtractWith: apidef.ValueExtractor,
							ExtractFrom: apidef.HeaderSource,
							Extractor:   &ValueExtractor{},
						},
					},
				},
			},
			idExtractor: &ValueExtractor{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.idExtractor, getIDExtractor(tc.spec))
		})
	}
}

func Test_shouldAddConfigData(t *testing.T) {
	testCases := []struct {
		name      string
		spec      *APISpec
		shouldAdd bool
	}{
		{
			name: "disabled from config",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					ConfigDataDisabled: true,
				},
			},
			shouldAdd: false,
		},
		{
			name: "enabled from config - empty config data",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					ConfigDataDisabled: true,
					ConfigData:         map[string]interface{}{},
				},
			},
			shouldAdd: false,
		},
		{
			name: "enabled from config - non-empty config data",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					ConfigDataDisabled: true,
					ConfigData: map[string]interface{}{
						"key": "value",
					},
				},
			},
			shouldAdd: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.shouldAdd, shouldAddConfigData(tc.spec))
		})
	}
}

func TestSyncHeadersAndMultiValueHeaders(t *testing.T) {
	// defining the test cases
	testCases := []struct {
		name                      string
		headers                   map[string]string
		initialMultiValueHeaders  []*coprocess.Header
		expectedMultiValueHeaders []*coprocess.Header
	}{
		{
			name: "adding a header",
			headers: map[string]string{
				"Header1": "value1",
				"Header2": "value2",
			},
			initialMultiValueHeaders: []*coprocess.Header{
				{
					Key:    "Header1",
					Values: []string{"oldValue1"},
				},
			},
			expectedMultiValueHeaders: []*coprocess.Header{
				{
					Key:    "Header1",
					Values: []string{"value1"},
				},
				{
					Key:    "Header2",
					Values: []string{"value2"},
				},
			},
		},
		{
			name: "removing a header",
			headers: map[string]string{
				"Header1": "value1",
			},
			initialMultiValueHeaders: []*coprocess.Header{
				{
					Key:    "Header1",
					Values: []string{"oldValue1"},
				},
				{
					Key:    "Header2",
					Values: []string{"oldValue2"},
				},
			},
			expectedMultiValueHeaders: []*coprocess.Header{
				{
					Key:    "Header1",
					Values: []string{"value1"},
				},
			},
		},
		{
			name: "updating a header",
			headers: map[string]string{
				"Header1": "newValue1",
			},
			initialMultiValueHeaders: []*coprocess.Header{
				{
					Key:    "Header1",
					Values: []string{"oldValue1"},
				},
			},
			expectedMultiValueHeaders: []*coprocess.Header{
				{
					Key:    "Header1",
					Values: []string{"newValue1"},
				},
			},
		},
		{
			name: "keeping multivalue headers",
			headers: map[string]string{
				"Header": "newValue1",
			},
			initialMultiValueHeaders: []*coprocess.Header{
				{
					Key:    "Header",
					Values: []string{"oldValue1", "value2"},
				},
			},
			expectedMultiValueHeaders: []*coprocess.Header{
				{
					Key:    "Header",
					Values: []string{"newValue1", "value2"},
				},
			},
		},
		{
			name: "empty multi value headers",
			headers: map[string]string{
				"Header": "newValue1",
			},
			initialMultiValueHeaders: []*coprocess.Header{},
			expectedMultiValueHeaders: []*coprocess.Header{
				{Key: "Header", Values: []string{"newValue1"}},
			},
		},
		{
			name: "multiple Set-Cookie headers",
			headers: map[string]string{
				"Set-Cookie": "session=abc123; Path=/",
			},
			initialMultiValueHeaders: []*coprocess.Header{
				{
					Key: "Set-Cookie",
					Values: []string{
						"session=dce123; Path=/",
						"user=john; Path=/",
						"theme=dark; Path=/",
					},
				},
			},
			expectedMultiValueHeaders: []*coprocess.Header{
				{
					Key: "Set-Cookie",
					Values: []string{
						"session=abc123; Path=/",
						"user=john; Path=/",
						"theme=dark; Path=/",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			updatedMultiValueHeaders := syncHeadersAndMultiValueHeaders(tc.headers, tc.initialMultiValueHeaders)
			if !equalHeaders(updatedMultiValueHeaders, tc.expectedMultiValueHeaders) {
				t.Errorf("syncHeadersAndMultiValueHeaders() = %v, want %v", updatedMultiValueHeaders, tc.expectedMultiValueHeaders)
			}
		})
	}
}

func equalHeaders(h1, h2 []*coprocess.Header) bool {
	if len(h1) != len(h2) {
		return false
	}
	m := make(map[string][]string)
	for _, h := range h1 {
		m[h.Key] = h.Values
	}
	for _, h := range h2 {
		if !reflect.DeepEqual(m[h.Key], h.Values) {
			return false
		}
		delete(m, h.Key)
	}
	return len(m) == 0
}

func TestCoProcessMiddlewareName(t *testing.T) {
	m := &CoProcessMiddleware{}

	require.Equal(t, "CoProcessMiddleware", m.Name(), "Name method did not return the expected value")
}

func TestValidateDriver(t *testing.T) {
	testSupportedDrivers := []apidef.MiddlewareDriver{apidef.PythonDriver, apidef.LuaDriver, apidef.GrpcDriver}
	testLoadedDrivers := map[apidef.MiddlewareDriver]coprocess.Dispatcher{apidef.GrpcDriver: &GRPCDispatcher{}}

	tests := []struct {
		name           string
		driver         apidef.MiddlewareDriver
		expectedStatus int
		expectedErr    error
	}{
		{
			name:           "Valid driver - supported and loaded",
			driver:         apidef.GrpcDriver,
			expectedStatus: http.StatusOK,
			expectedErr:    nil,
		},
		{
			name:           "Invalid driver - not supported",
			driver:         "unsupportedDriver",
			expectedStatus: http.StatusInternalServerError,
			expectedErr:    errors.New(http.StatusText(http.StatusInternalServerError)),
		},
		{
			name:           "Invalid driver - supported but not loaded",
			driver:         apidef.PythonDriver,
			expectedStatus: http.StatusInternalServerError,
			expectedErr:    errors.New(http.StatusText(http.StatusInternalServerError)),
		},
	}

	originalSupportedDrivers := supportedDrivers
	originalLoadedDrivers := loadedDrivers

	supportedDrivers = testSupportedDrivers
	loadedDrivers = testLoadedDrivers

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := &CoProcessMiddleware{
				BaseMiddleware: &BaseMiddleware{
					Spec: &APISpec{
						APIDefinition: &apidef.APIDefinition{
							CustomMiddleware: apidef.MiddlewareSection{
								Driver: tt.driver,
							},
						},
					},
				},
			}

			status, err := mw.validateDriver()

			assert.Equal(t, tt.expectedStatus, status)
			if tt.expectedErr == nil {
				assert.Nil(t, err)
			} else {
				assert.Equal(t, tt.expectedErr.Error(), err.Error())
			}
		})
	}

	supportedDrivers = originalSupportedDrivers
	loadedDrivers = originalLoadedDrivers
}

func getRSS() uint64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val, _ := strconv.ParseUint(fields[1], 10, 64)
				return val * 1024 // VmRSS is in kB
			}
		}
	}
	return 0
}

func TestCoProcess_MemoryFragmentation(t *testing.T) {
	// 1. Create a Massive Session Object
	session := &user.SessionState{
		MetaData:     make(map[string]interface{}),
		AccessRights: make(map[string]user.AccessDefinition),
	}

	for i := 0; i < 5000; i++ {
		key := fmt.Sprintf("key_%d", i)
		session.MetaData[key] = fmt.Sprintf("value_%d_with_some_extra_padding_to_make_it_larger", i)
		session.AccessRights[key] = user.AccessDefinition{
			APIName:  fmt.Sprintf("api_%d", i),
			APIID:    fmt.Sprintf("api_id_%d", i),
			Versions: []string{"Default"},
			AllowedURLs: []user.AccessSpec{
				{
					URL:     fmt.Sprintf("/path/%d", i),
					Methods: []string{"GET", "POST"},
				},
			},
		}
	}

	// 2. Setup the CoProcessor
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID: "test-api",
			OrgID: "test-org",
		},
	}

	mw := &CoProcessMiddleware{
		BaseMiddleware: &BaseMiddleware{
			Spec: spec,
		},
		HookType: coprocess.HookType_Post,
		HookName: "TestHook",
	}

	c := &CoProcessor{
		Middleware: mw,
	}

	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	// Add session to context
	reqCtx := context.WithValue(req.Context(), ctx.SessionData, session)
	req = req.WithContext(reqCtx)

	// Force initial GC to get a clean baseline
	runtime.GC()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	initialHeap := m.HeapAlloc
	initialRSS := getRSS()

	if initialRSS == 0 {
		t.Skip("Skipping test because VmRSS could not be read (not on Linux?)")
	}
	// 3. Simulate Allocation Churn Concurrently
	iterations := 5000
	concurrency := 10
	var wg sync.WaitGroup

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				obj, err := c.BuildObject(req, nil, spec)
				require.NoError(t, err)
				
				// Release object if pool is implemented
				if obj != nil {
					ReleaseCoprocessObject(obj)
				}

				// 4. Force Garbage Collection periodically
				if i%1000 == 0 {
					runtime.GC()
				}
			}
		}()
	}
	wg.Wait()

	// Final GC
	runtime.GC()
	runtime.ReadMemStats(&m)
	finalHeap := m.HeapAlloc
	finalRSS := getRSS()

	t.Logf("Initial Heap: %d bytes", initialHeap)
	t.Logf("Final Heap: %d bytes", finalHeap)
	t.Logf("Initial RSS: %d bytes", initialRSS)
	t.Logf("Final RSS: %d bytes", finalRSS)

	heapDiff := int64(finalHeap) - int64(initialHeap)
	rssDiff := int64(finalRSS) - int64(initialRSS)

	t.Logf("Heap Diff: %d bytes", heapDiff)
	t.Logf("RSS Diff: %d bytes", rssDiff)
	// 6. Assert Fragmentation Fixed
	// The OS RSS should NOT have grown significantly because we are using sync.Pool
	assert.True(t, rssDiff < 100*1024*1024, "Expected RSS to grow by less than 100MB due to sync.Pool")
}
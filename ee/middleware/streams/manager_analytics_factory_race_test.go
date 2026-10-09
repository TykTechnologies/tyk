package streams

import (
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestManagerAnalyticsFactoryConcurrentReadAndReplacement(t *testing.T) {
	manager := &Manager{}
	const iterations = 1000
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			manager.SetAnalyticsFactory(&NoopStreamAnalyticsFactory{})
		}
	}()
	go func() {
		defer wg.Done()
		request := httptest.NewRequest("GET", "/", nil)
		for i := 0; i < iterations; i++ {
			factory := manager.getAnalyticsFactory()
			require.NotNil(t, factory.CreateRecorder(request))
		}
	}()
	wg.Wait()
}

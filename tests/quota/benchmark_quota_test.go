package quota

import (
	"net/http"
	"sync"
	"testing"

	"github.com/TykTechnologies/tyk/internal/uuid"
	"github.com/TykTechnologies/tyk/test"
)

func BenchmarkQuota(b *testing.B) {
	ts := StartTest(nil)
	defer ts.Close()

	settings := map[string]interface{}{
		"quota_max":          100000000,
		"quota_remaining":    100000000,
		"quota_renewal_rate": 300,
	}

	setupQuotaLimit(b, ts, "key-"+uuid.New(), settings)

	var wg sync.WaitGroup

	run := func() {
		for i := 0; i < b.N; i++ {
			ts.Run(b, test.TestCase{
				Code: http.StatusOK,
			})
		}
		wg.Done()
	}

	wg.Add(4)

	go run()
	go run()
	go run()
	go run()

	wg.Wait()
}

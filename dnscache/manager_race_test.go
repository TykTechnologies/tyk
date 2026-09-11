package dnscache

// Reproduction test for a data race in the `random` multiple-IPs strategy.
//
// FAILS ON MASTER UNDER -race BY DESIGN.
//
//	go test ./dnscache/ -run TestDnsCacheManager_RandomStrategy_Race -race -count=1
//
// getRandomIp (manager.go:127-144) lazily initialises the shared *rand.Rand:
//
//	if m.rand == nil {
//	    source := rand.NewSource(time.Now().Unix())
//	    m.rand = rand.New(source)
//	}
//	ip := ips[m.rand.Intn(len(ips))]
//
// DnsCacheManager (manager.go:45-49) has no mutex, and doCachedDial — which
// reaches getRandomIp — is the transport's DialContext, so it runs concurrently
// on every upstream dial. Two races are present:
//
//  1. the nil-check/assign of m.rand is a read-write race between goroutines;
//  2. math/rand.Rand is explicitly NOT safe for concurrent use, so the
//     concurrent Intn calls race on the source's internal state.
//
// This only fires when dns_cache.enabled is true AND
// multiple_ips_handle_strategy is "random" AND the host resolves to more than
// one address — i.e. precisely the headless-Service topology this work is
// about. That is why it has gone unnoticed: the default strategy is no_cache
// and the default for dns_cache.enabled is false.

import (
	"sync"
	"testing"

	"github.com/TykTechnologies/tyk/config"
)

func TestDnsCacheManager_RandomStrategy_Race(t *testing.T) {
	mgr := NewDnsCacheManager(config.RandomStrategy)

	// A multi-address answer, as a headless Service produces.
	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}

	const goroutines = 32
	const iterations = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				if _, err := mgr.getRandomIp(ips); err != nil {
					t.Errorf("getRandomIp: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	// Under -race this test fails inside getRandomIp before reaching here.
	// Without -race it passes, which is why the race has gone unnoticed.
}

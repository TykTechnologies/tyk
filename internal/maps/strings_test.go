package maps

import (
	"strconv"
	"sync"
	"testing"
)

// Verifies: STK-REQ-022, SYS-REQ-110, SW-REQ-030
// STK-REQ-022:nominal:nominal
// STK-REQ-022:boundary:boundary
// SYS-REQ-110:nominal:nominal
// SYS-REQ-110:boundary:boundary
// SW-REQ-030:nominal:nominal
// SW-REQ-030:boundary:boundary
func TestStringMap_SetGet(t *testing.T) {
	m := NewStringMap()

	if got, ok := m.Get("missing"); ok || got != "" {
		t.Fatalf("Get missing = %q, %v; want empty false", got, ok)
	}

	m.Set("key", "value")
	got, ok := m.Get("key")
	if !ok || got != "value" {
		t.Fatalf("Get key = %q, %v; want value true", got, ok)
	}
}

// Verifies: STK-REQ-022, SYS-REQ-110, SW-REQ-030
// STK-REQ-022:concurrent:race
// SYS-REQ-110:concurrent:race
// SW-REQ-030:concurrent:race
func TestStringMap_ConcurrentSetGet(t *testing.T) {
	m := NewStringMap()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			key := strconv.Itoa(i)
			m.Set(key, key)
			if got, ok := m.Get(key); ok && got != key {
				t.Errorf("Get(%q) = %q, want %q", key, got, key)
			}
		}()
	}
	wg.Wait()
}

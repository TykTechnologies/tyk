package storage

import (
	"testing"
)

// These benchmarks back the "no performance degradation" criterion for the TT-16259
// fix: the session UPDATE path switches from an unconditional SET (SetKey) to a
// conditional set-if-exists (SetKeyEx -> SET ... XX). Both are a single Redis
// round-trip, so SetKeyEx should match SetKey on ns/op and allocs. To measure the
// real write cost (not the XX no-op), the key is seeded so the conditional write hits.
//
// Run:  go test -run '^$' -bench 'BenchmarkRedisClusterSet' -benchmem ./storage/

const benchSessionValue = `{"allowance":-1,"rate":-1,"per":-1,"quota_max":100000000,` +
	`"quota_renewal_rate":3600,"quota_remaining":99999999,"org_id":"bench-org",` +
	`"access_rights":{"api1":{"api_id":"api1","api_name":"bench","versions":["Default"]}}}`

func benchStore(prefix string) *RedisCluster {
	return &RedisCluster{KeyPrefix: prefix, ConnectionHandler: rc}
}

func BenchmarkRedisClusterSetKey(b *testing.B) {
	store := benchStore("bench-setkey-")
	const key = "k"
	if err := store.SetKey(key, benchSessionValue, 0); err != nil { // seed
		b.Fatal(err)
	}
	b.Cleanup(func() { store.DeleteKey(key) })

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := store.SetKey(key, benchSessionValue, 0); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRedisClusterSetKeyEx(b *testing.B) {
	store := benchStore("bench-setkeyex-")
	const key = "k"
	if err := store.SetKey(key, benchSessionValue, 0); err != nil { // seed so XX writes
		b.Fatal(err)
	}
	b.Cleanup(func() { store.DeleteKey(key) })

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := store.SetKeyEx(key, benchSessionValue, 0); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRedisClusterSetRawKey(b *testing.B) {
	store := benchStore("bench-setrawkey-")
	const key = "bench-setrawkey-k"
	if err := store.SetRawKey(key, benchSessionValue, 0); err != nil { // seed
		b.Fatal(err)
	}
	b.Cleanup(func() { store.DeleteRawKey(key) })

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := store.SetRawKey(key, benchSessionValue, 0); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRedisClusterSetRawKeyEx(b *testing.B) {
	store := benchStore("bench-setrawkeyex-")
	const key = "bench-setrawkeyex-k"
	if err := store.SetRawKey(key, benchSessionValue, 0); err != nil { // seed so XX writes
		b.Fatal(err)
	}
	b.Cleanup(func() { store.DeleteRawKey(key) })

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := store.SetRawKeyEx(key, benchSessionValue, 0); err != nil {
			b.Fatal(err)
		}
	}
}

package user

import (
	"testing"
)

func BenchmarkHash(b *testing.B) {
	s := SessionState{
		Allowance:        1000.0,
		Rate:             1000.0,
		Per:              1,
		Expires:          1458669677,
		QuotaRemaining:   1000,
		QuotaRenewalRate: 3600,
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		{
			s.Hash()
		}
	}
}

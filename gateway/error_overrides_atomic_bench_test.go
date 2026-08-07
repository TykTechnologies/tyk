package gateway

import (
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
)

func BenchmarkAtomicLoadOverhead(b *testing.B) {
	b.Run("atomic load - nil pointer", func(b *testing.B) {
		gw := &Gateway{}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = gw.GetCompiledErrorOverrides()
		}
	})

	b.Run("atomic load - non-nil pointer", func(b *testing.B) {
		gw := &Gateway{}
		overrides := apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{Response: apidef.ErrorResponse{Message: "test"}},
			},
		}
		compiled := CompileErrorOverrides(overrides)
		gw.SetCompiledErrorOverrides(compiled)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = gw.GetCompiledErrorOverrides()
		}
	})

	b.Run("atomic load + nil check + branch", func(b *testing.B) {
		gw := &Gateway{}
		var result bool

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if gw.GetCompiledErrorOverrides() != nil {
				result = true
			} else {
				result = false
			}
		}
		_ = result
	})

	b.Run("no atomic load - direct path", func(b *testing.B) {
		var result bool

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			result = false
		}
		_ = result
	})
}

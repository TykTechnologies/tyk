package reflect

import (
	stdreflect "reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type reqproofNested struct {
	Enabled bool
	Labels  []string
}

type reqproofSample struct {
	Name   string
	Count  int
	Values []int
	Nested reqproofNested
}

// Verifies: SYS-REQ-104, SW-REQ-065
// SW-REQ-065:nominal:nominal
// SW-REQ-065:boundary:nominal
// SW-REQ-065:error_handling:nominal
// SW-REQ-065:error_handling:negative
// SW-REQ-065:determinism:nominal
func TestReflectSupportHelpersPreserveModelUtilityBehavior(t *testing.T) {
	t.Run("clone returns deep copy and preserves value shape", func(t *testing.T) {
		original := reqproofSample{
			Name:   "pets",
			Count:  2,
			Values: []int{1, 2},
			Nested: reqproofNested{
				Enabled: true,
				Labels:  []string{"public"},
			},
		}

		first := Clone(original)
		second := Clone(original)

		require.Equal(t, original, first)
		require.Equal(t, first, second)

		first.Values[0] = 99
		first.Nested.Labels[0] = "changed"
		require.Equal(t, []int{1, 2}, original.Values)
		require.Equal(t, []string{"public"}, original.Nested.Labels)
	})

	t.Run("empty detection treats OAS empty containers as zero values", func(t *testing.T) {
		falsePtr := false
		truePtr := true

		require.True(t, IsEmpty(reqproofSample{}))
		require.True(t, IsEmpty(reqproofSample{Values: []int{}, Nested: reqproofNested{Labels: []string{}}}))
		require.False(t, IsEmpty(reqproofSample{Name: "pets"}))
		require.False(t, IsEmpty(reqproofSample{Nested: reqproofNested{Enabled: true}}))
		require.True(t, IsZero(stdreflect.ValueOf((*reqproofNested)(nil))))
		require.True(t, IsZero(stdreflect.ValueOf(&reqproofNested{})))
		require.False(t, IsZero(stdreflect.ValueOf(&falsePtr)))
		require.False(t, IsZero(stdreflect.ValueOf(&truePtr)))
		require.False(t, IsZero(stdreflect.ValueOf([]string{"configured"})))
	})

	t.Run("cast converts JSON-compatible values and rejects unmarshalable inputs", func(t *testing.T) {
		type castTarget struct {
			Name  string
			Count int
		}

		got, err := Cast[castTarget](map[string]any{"Name": "pets", "Count": 3})
		require.NoError(t, err)
		require.Equal(t, castTarget{Name: "pets", Count: 3}, *got)

		again, err := Cast[castTarget](map[string]any{"Name": "pets", "Count": 3})
		require.NoError(t, err)
		require.Equal(t, *got, *again)

		_, err = Cast[map[string]any](make(chan int))
		require.Error(t, err)
	})

	t.Run("flatten coalesces nested maps slices structs and numeric values", func(t *testing.T) {
		flat, err := Flatten(map[string]any{
			"enabled": true,
			"count":   int64(7),
			"ratio":   float32(1.5),
			"nested": map[string]any{
				"name": "pets",
				"ids":  []any{uint(1), nil},
			},
			"struct": reqproofNested{
				Enabled: true,
				Labels:  []string{"a", "b"},
			},
		})
		require.NoError(t, err)

		expected := FlatMap{
			"enabled":         true,
			"count":           float64(7),
			"ratio":           float64(float32(1.5)),
			"nested.name":     "pets",
			"nested.ids.0":    float64(1),
			"nested.ids.1":    "",
			"struct.Enabled":  true,
			"struct.Labels.0": "a",
			"struct.Labels.1": "b",
		}
		require.Equal(t, expected, flat)

		repeated, err := Flatten(map[string]any{
			"enabled": true,
			"count":   int64(7),
		})
		require.NoError(t, err)
		require.Equal(t, FlatMap{"enabled": true, "count": float64(7)}, repeated)
	})

	t.Run("flatten reports unsupported values and rejects non-string map keys", func(t *testing.T) {
		_, err := Flatten(map[string]any{"fn": func() {}})
		require.Error(t, err)
		require.True(t, strings.HasPrefix(err.Error(), "Unknown: "))

		require.Panics(t, func() {
			_, _ = Flatten(map[string]any{
				"bad": map[any]any{1: "one"},
			})
		})
	})
}

package option

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type sampleConfig struct {
	Name  string
	Count int
	Seen  []string
}

// Verifies: STK-REQ-035, SYS-REQ-123, SW-REQ-110
// STK-REQ-035:STK-REQ-035-AC-01:acceptance
// SW-REQ-110:nominal:nominal
// SW-REQ-110:boundary:nominal
// MCDC SYS-REQ-123: option_builder_operation_requested=F, option_builder_result_determined=F => TRUE
// MCDC SYS-REQ-123: option_builder_operation_requested=T, option_builder_result_determined=T => TRUE
//
//mcdc:ignore SYS-REQ-123: option_builder_operation_requested=T, option_builder_result_determined=F => FALSE -- violation row is the negation of the local option builder helper guarantee; these tests assert requested option builder operations preserve supplied option slices and apply options in order to a copy of the base value [category: defensive] [reviewed: agent:codex]
func TestNew(t *testing.T) {
	opts := []Option[sampleConfig]{
		func(cfg *sampleConfig) {
			cfg.Name = "first"
		},
		func(cfg *sampleConfig) {
			cfg.Count = 2
		},
	}

	got := New(opts)

	require.Len(t, got, 2)
	assert.Equal(t, Options[sampleConfig](opts), got)
}

// Verifies: STK-REQ-035, SYS-REQ-123, SW-REQ-110
// STK-REQ-035:STK-REQ-035-AC-02:acceptance
// SW-REQ-110:nominal:nominal
// SW-REQ-110:boundary:nominal
func TestOptionsBuild(t *testing.T) {
	tests := []struct {
		name string
		base sampleConfig
		opts Options[sampleConfig]
		want sampleConfig
	}{
		{
			name: "empty options return copy of base",
			base: sampleConfig{Name: "base", Count: 1},
			opts: nil,
			want: sampleConfig{Name: "base", Count: 1},
		},
		{
			name: "options apply in order",
			base: sampleConfig{Name: "base", Count: 1},
			opts: Options[sampleConfig]{
				func(cfg *sampleConfig) {
					cfg.Seen = append(cfg.Seen, cfg.Name)
					cfg.Name = "first"
				},
				func(cfg *sampleConfig) {
					cfg.Seen = append(cfg.Seen, cfg.Name)
					cfg.Count++
				},
				func(cfg *sampleConfig) {
					cfg.Seen = append(cfg.Seen, "count")
				},
			},
			want: sampleConfig{
				Name:  "first",
				Count: 2,
				Seen:  []string{"base", "first", "count"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := tt.base

			got := tt.opts.Build(base)

			require.NotNil(t, got)
			assert.Equal(t, tt.want, *got)
			assert.Equal(t, tt.base, base)
		})
	}
}

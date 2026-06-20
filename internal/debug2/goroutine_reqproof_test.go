package debug2

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func recordFromDump(dump string) *Record {
	return &Record{buffer: bytes.NewBufferString(dump)}
}

// Verifies: STK-REQ-044, SYS-REQ-132, SW-REQ-119
// STK-REQ-044:STK-REQ-044-AC-01:acceptance
// STK-REQ-044:STK-REQ-044-AC-02:acceptance
// MCDC SYS-REQ-132: goroutine_debug_record_operation_terminal=T => TRUE
// SW-REQ-119:nominal:nominal
// SW-REQ-119:boundary:nominal
// SW-REQ-119:determinism:nominal
//
//mcdc:ignore SYS-REQ-132: goroutine_debug_record_operation_terminal=F => FALSE -- the onboarded goroutine debug record operations are synchronous local helpers that either parse records, apply ignore filtering, return a diff record, return a count, or format a string before returning; a non-terminal result is not a reachable runtime state for these APIs [category: defensive] [reviewed: human:buger]
func TestGoroutineDebugRecordPreservesLocalBehavior(t *testing.T) {
	const baselineDump = `1 @ 0x100
main.first()
	/first.go:10
2 @ 0x200
main.second()
	/second.go:20
`
	const laterDump = `1 @ 0x100
main.first()
	/first.go:10
2 @ 0x200
main.second()
	/second.go:20
3 @ 0x300
main.third()
	/third.go:30
`

	t.Run("parse count and string format records", func(t *testing.T) {
		record := recordFromDump(baselineDump)

		parsed := record.parseGoroutines()
		assert.Len(t, parsed, 2)
		assert.Equal(t, []string{"1 @ 0x100", "main.first()", "\t/first.go:10"}, parsed["1 @ 0x100"])
		assert.Equal(t, 2, record.Count())

		formatted := record.String()
		assert.Contains(t, formatted, "Number of goroutines: 2")
		assert.Contains(t, formatted, "main.first()")
		assert.Contains(t, formatted, "main.second()")
	})

	t.Run("ignore filtering removes matching goroutine record", func(t *testing.T) {
		record := recordFromDump(baselineDump)
		record.SetIgnores([]string{"main.second"})

		parsed := record.parseGoroutines()
		assert.Len(t, parsed, 1)
		assert.Contains(t, parsed, "1 @ 0x100")
		assert.NotContains(t, parsed, "2 @ 0x200")
	})

	t.Run("since returns only records absent from previous snapshot", func(t *testing.T) {
		baseline := recordFromDump(baselineDump)
		later := recordFromDump(laterDump)

		diff := later.Since(baseline)
		assert.Equal(t, 1, diff.Count())
		diffText := diff.String()
		assert.Contains(t, diffText, "3 @ 0x300")
		assert.Contains(t, diffText, "main.third()")
		assert.False(t, strings.Contains(diffText, "main.first()"))
	})
}

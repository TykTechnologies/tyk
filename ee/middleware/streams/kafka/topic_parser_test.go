package kafka

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseTopicsRangesOffsetsDuplicatesAndValidation(t *testing.T) {
	topics, partitions, err := parseTopics([]string{"plain, ranged:1-3:42", " ranged:2 ", "plain"}, -1, true)
	require.NoError(t, err)
	require.Equal(t, []string{"plain", "plain"}, topics)
	require.Equal(t, map[int32]int64{1: 42, 2: 42, 3: 42}, partitions["ranged"], "explicit offset must win over a later default duplicate")

	for _, tc := range []struct {
		name     string
		topics   []string
		offsets  bool
		contains string
	}{
		{"too many fields", []string{"topic:0:1:2"}, true, "only one partition"},
		{"offset forbidden", []string{"topic:0:1"}, false, "explicit offsets"},
		{"empty partition", []string{"topic:"}, true, "empty partition"},
		{"invalid range", []string{"topic:1-2-3"}, true, "only one range"},
		{"invalid start", []string{"topic:x-2"}, true, "start of range"},
		{"invalid end", []string{"topic:1-x"}, true, "end of range"},
		{"invalid offset", []string{"topic:1:nope"}, true, "invalid syntax"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parseTopics(tc.topics, -1, tc.offsets)
			require.ErrorContains(t, err, tc.contains)
		})
	}
}

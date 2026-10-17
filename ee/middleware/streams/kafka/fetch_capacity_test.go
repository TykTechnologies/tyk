package kafka

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAssignmentStateAndPartitionDifference(t *testing.T) {
	var state assignmentState
	state.add(map[string][]int32{"a": {0, 1}, "b": {2}})
	state.add(map[string][]int32{"a": {1, 3}})
	assert.Equal(t, map[string][]int32{"a": {0, 1, 3}, "b": {2}}, state.snapshot())
	state.remove(map[string][]int32{"a": {1}, "b": {2}})
	assert.Equal(t, map[string][]int32{"a": {0, 3}}, state.snapshot())
	assert.Equal(t, map[string][]int32{"a": {3}}, partitionDifference(state.snapshot(), map[string][]int32{"a": {0}}))
}

func TestPartitionMapHelpersDoNotAliasOrDuplicate(t *testing.T) {
	source := map[string][]int32{"topic": {1}}
	clone := clonePartitionMap(source)
	clone["topic"][0] = 2
	assert.Equal(t, int32(1), source["topic"][0])
	assert.Equal(t, []int32{1, 2}, appendUniquePartition([]int32{1}, 2))
	assert.Equal(t, []int32{1}, appendUniquePartition([]int32{1}, 1))
}

func TestCapacityRecoveryKeepsOwnershipPendingPartitionsPaused(t *testing.T) {
	capacityPaused := map[string][]int32{"events": {0, 1}, "audit": {2}}
	ownershipPending := map[string][]int32{"events": {1}}

	assert.Equal(t, map[string][]int32{"events": {0}, "audit": {2}}, partitionDifference(capacityPaused, ownershipPending))
}

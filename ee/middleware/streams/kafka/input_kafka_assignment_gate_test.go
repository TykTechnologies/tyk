package kafka

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPartitionMayResumeRequiresOwnershipPublication(t *testing.T) {
	require.False(t, partitionMayResume(true, true, true, false, true),
		"the normal pause reconciliation must not ungate a partition before ownership publication")
	require.False(t, partitionMayResume(true, true, true, true, false),
		"ownership publication must not bypass a full global capacity gate")
	require.True(t, partitionMayResume(true, true, true, true, true))
}

func TestAcknowledgmentGroupCommitOptions(t *testing.T) {
	require.Len(t, acknowledgmentGroupCommitOptions(AcknowledgmentModeOutput, time.Second), 2)
	require.Len(t, acknowledgmentGroupCommitOptions(AcknowledgmentModeExternal, time.Second), 1,
		"external acknowledgment must install franz-go DisableAutoCommit")
	require.Empty(t, acknowledgmentGroupCommitOptions("unknown", time.Second))
}

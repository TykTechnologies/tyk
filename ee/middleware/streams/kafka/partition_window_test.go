package kafka

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newTestWindow(t *testing.T, epoch uint64, base int64, limits WindowLimits) *PartitionAckWindow {
	t.Helper()
	w, err := NewPartitionAckWindow("topic", 2, epoch, base, limits)
	require.NoError(t, err)
	return w
}

func TestPartitionAckWindowOutOfOrderAndGaps(t *testing.T) {
	w := newTestWindow(t, 3, 10, WindowLimits{})
	for _, offset := range []int64{10, 11, 12} {
		require.NoError(t, w.Track(3, DeliveredRecord{Offset: offset, LeaderEpoch: 4, Bytes: 10}))
	}
	commit, err := w.Acknowledge(3, 12)
	require.NoError(t, err)
	require.Nil(t, commit)
	commit, err = w.Acknowledge(3, 10)
	require.NoError(t, err)
	require.Equal(t, &CommitPoint{Topic: "topic", Partition: 2, RecordOffset: 10, NextOffset: 11, LeaderEpoch: 4}, commit)
	commit, err = w.Acknowledge(3, 12) // idempotent, still blocked by 11
	require.NoError(t, err)
	require.Nil(t, commit)
	commit, err = w.Acknowledge(3, 11)
	require.NoError(t, err)
	require.Equal(t, int64(12), commit.RecordOffset)
	require.Equal(t, int64(13), commit.NextOffset)
	require.Equal(t, int32(4), commit.LeaderEpoch)
	records, bytes := w.Pending()
	require.Zero(t, records)
	require.Zero(t, bytes)
	commit, err = w.Acknowledge(3, 10) // already safely committed
	require.NoError(t, err)
	require.Nil(t, commit)
}

func TestPartitionAckWindowAdvancesFromFirstActuallyDeliveredOffset(t *testing.T) {
	w := newTestWindow(t, 1, 5, WindowLimits{})
	require.NoError(t, w.Track(1, DeliveredRecord{Offset: 6}))
	commit, err := w.Acknowledge(1, 6)
	require.NoError(t, err)
	require.Equal(t, int64(7), commit.NextOffset)
	require.Equal(t, int64(7), w.NextOffset())
	_, err = w.Acknowledge(1, 5)
	require.NoError(t, err)
	require.ErrorIs(t, w.Track(1, DeliveredRecord{Offset: 5}), ErrOffsetBeforeBase)
}

func TestPartitionAckWindowAdvancesAcrossKafkaOffsetGaps(t *testing.T) {
	w := newTestWindow(t, 1, 100, WindowLimits{})
	require.NoError(t, w.Track(1, DeliveredRecord{Offset: 100}))
	require.NoError(t, w.Track(1, DeliveredRecord{Offset: 102, LeaderEpoch: 9}))
	commit, err := w.Acknowledge(1, 102)
	require.NoError(t, err)
	require.Nil(t, commit)
	commit, err = w.Acknowledge(1, 100)
	require.NoError(t, err)
	require.Equal(t, &CommitPoint{Topic: "topic", Partition: 2, RecordOffset: 102, NextOffset: 103, LeaderEpoch: 9}, commit)
	require.Equal(t, int64(103), w.NextOffset())
}

func TestPartitionAckWindowRejectsOutOfOrderDeliveryAcrossGap(t *testing.T) {
	w := newTestWindow(t, 1, 100, WindowLimits{})
	require.NoError(t, w.Track(1, DeliveredRecord{Offset: 102}))
	require.ErrorIs(t, w.Track(1, DeliveredRecord{Offset: 100}), ErrDeliveryOrder)
}

func TestPartitionAckWindowEpochReset(t *testing.T) {
	w := newTestWindow(t, 8, 20, WindowLimits{})
	require.NoError(t, w.Track(8, DeliveredRecord{Offset: 20, Bytes: 2}))
	require.ErrorIs(t, w.Track(7, DeliveredRecord{Offset: 21}), ErrStaleEpoch)
	_, err := w.Acknowledge(7, 20)
	require.ErrorIs(t, err, ErrStaleEpoch)
	require.ErrorIs(t, w.ResetEpoch(8, 1), ErrStaleEpoch)
	require.NoError(t, w.ResetEpoch(9, 4))
	require.Equal(t, uint64(9), w.Epoch())
	require.Equal(t, int64(4), w.NextOffset())
	records, bytes := w.Pending()
	require.Zero(t, records)
	require.Zero(t, bytes)
	_, err = w.Acknowledge(8, 20)
	require.ErrorIs(t, err, ErrStaleEpoch)
}

func TestPartitionAckWindowBoundsAndDuplicateDelivery(t *testing.T) {
	w := newTestWindow(t, 1, 0, WindowLimits{MaxRecords: 2, MaxBytes: 10})
	deadline := time.Unix(100, 0)
	require.NoError(t, w.Track(1, DeliveredRecord{Offset: 0, Bytes: 6, Deadline: deadline}))
	require.NoError(t, w.Track(1, DeliveredRecord{Offset: 0, Bytes: 6, Deadline: deadline}))
	records, bytes := w.Pending()
	require.Equal(t, 1, records)
	require.Equal(t, int64(6), bytes)
	require.Error(t, w.Track(1, DeliveredRecord{Offset: 0, Bytes: 5, Deadline: deadline}))
	require.NoError(t, w.Track(1, DeliveredRecord{Offset: 1, Bytes: 4}))
	require.ErrorIs(t, w.Track(1, DeliveredRecord{Offset: 2}), ErrWindowFull)
	require.ErrorIs(t, w.Track(1, DeliveredRecord{Offset: 2, Bytes: 1}), ErrWindowFull)
	_, err := w.Acknowledge(1, 0)
	require.NoError(t, err)
	require.NoError(t, w.Track(1, DeliveredRecord{Offset: 2, Bytes: 6}))
	require.ErrorIs(t, w.Track(1, DeliveredRecord{Offset: 0}), ErrOffsetBeforeBase)
}

func TestPartitionAckWindowDeadlineState(t *testing.T) {
	w := newTestWindow(t, 1, 0, WindowLimits{})
	now := time.Unix(100, 0)
	require.NoError(t, w.Track(1, DeliveredRecord{Offset: 0, Deadline: now.Add(time.Second)}))
	require.NoError(t, w.Track(1, DeliveredRecord{Offset: 1, Deadline: now.Add(-time.Second)}))
	require.NoError(t, w.Track(1, DeliveredRecord{Offset: 2}))
	state := w.DeadlineState(now)
	require.Equal(t, now.Add(-time.Second), state.Earliest)
	require.Equal(t, 1, state.ExpiredCount)
	_, err := w.Acknowledge(1, 0)
	require.NoError(t, err)
	state = w.DeadlineState(now.Add(time.Second))
	require.Equal(t, 1, state.ExpiredCount)
}

func TestPartitionAckWindowValidation(t *testing.T) {
	_, err := NewPartitionAckWindow("", 0, 1, 0, WindowLimits{})
	require.Error(t, err)
	_, err = NewPartitionAckWindow("t", -1, 1, 0, WindowLimits{})
	require.Error(t, err)
	w := newTestWindow(t, 1, 0, WindowLimits{})
	require.Error(t, w.Track(1, DeliveredRecord{Offset: 0, Bytes: -1}))
	require.Error(t, w.ResetEpoch(2, -1))
}

func TestPartitionAckWindowConcurrentOutOfOrderAcks(t *testing.T) {
	const count = 100
	w := newTestWindow(t, 1, 0, WindowLimits{MaxRecords: count})
	for offset := int64(0); offset < count; offset++ {
		require.NoError(t, w.Track(1, DeliveredRecord{Offset: offset, Bytes: 1}))
	}
	var wg sync.WaitGroup
	for offset := int64(count - 1); offset >= 0; offset-- {
		wg.Add(1)
		go func(offset int64) {
			defer wg.Done()
			_, err := w.Acknowledge(1, offset)
			require.NoError(t, err)
		}(offset)
	}
	wg.Wait()
	require.Equal(t, int64(count), w.NextOffset())
	records, bytes := w.Pending()
	require.Zero(t, records)
	require.Zero(t, bytes)
}

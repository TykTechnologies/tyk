package kafka

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrStaleEpoch       = errors.New("stale delivery epoch")
	ErrWindowFull       = errors.New("partition acknowledgement window full")
	ErrUnknownDelivery  = errors.New("unknown delivered offset")
	ErrOffsetBeforeBase = errors.New("offset is before partition window base")
	ErrDeliveryOrder    = errors.New("delivered offsets are not ordered")
)

type WindowLimits struct {
	MaxRecords int
	MaxBytes   int64
}

type DeliveredRecord struct {
	Offset      int64
	LeaderEpoch int32
	Bytes       int64
	Deadline    time.Time
}

type CommitPoint struct {
	Topic        string
	Partition    int32
	RecordOffset int64
	NextOffset   int64
	LeaderEpoch  int32
}

type DeadlineState struct {
	Earliest     time.Time
	ExpiredCount int
}

type windowRecord struct {
	bytes       int64
	leaderEpoch int32
	deadline    time.Time
	acked       bool
}

// PartitionAckWindow tracks delivered records and advances only across a
// contiguous acknowledged prefix. It is safe for concurrent delivery and ack.
type PartitionAckWindow struct {
	mu        sync.Mutex
	topic     string
	partition int32
	epoch     uint64
	base      int64
	limits    WindowLimits
	records   map[int64]windowRecord
	order     []int64
	bytes     int64
}

func NewPartitionAckWindow(topic string, partition int32, epoch uint64, nextOffset int64, limits WindowLimits) (*PartitionAckWindow, error) {
	if topic == "" || partition < 0 || nextOffset < 0 || limits.MaxRecords < 0 || limits.MaxBytes < 0 {
		return nil, errors.New("invalid partition acknowledgement window configuration")
	}
	return &PartitionAckWindow{topic: topic, partition: partition, epoch: epoch, base: nextOffset, limits: limits, records: map[int64]windowRecord{}}, nil
}

func (w *PartitionAckWindow) Track(epoch uint64, record DeliveredRecord) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if epoch != w.epoch {
		return ErrStaleEpoch
	}
	if record.Offset < w.base {
		return ErrOffsetBeforeBase
	}
	if record.Bytes < 0 {
		return errors.New("negative delivered record size")
	}
	if existing, ok := w.records[record.Offset]; ok {
		if existing.bytes == record.Bytes && existing.leaderEpoch == record.LeaderEpoch && existing.deadline.Equal(record.Deadline) {
			return nil
		}
		return fmt.Errorf("offset %d already tracked with different metadata", record.Offset)
	}
	if len(w.order) > 0 && record.Offset <= w.order[len(w.order)-1] {
		return ErrDeliveryOrder
	}
	if w.limits.MaxRecords > 0 && len(w.records)+1 > w.limits.MaxRecords {
		return ErrWindowFull
	}
	if w.limits.MaxBytes > 0 && w.bytes+record.Bytes > w.limits.MaxBytes {
		return ErrWindowFull
	}
	w.records[record.Offset] = windowRecord{bytes: record.Bytes, leaderEpoch: record.LeaderEpoch, deadline: record.Deadline}
	w.order = append(w.order, record.Offset)
	w.bytes += record.Bytes
	return nil
}

// Acknowledge is idempotent and returns a commit point only when the safe
// contiguous prefix advances. NextOffset is the value Kafka must commit.
func (w *PartitionAckWindow) Acknowledge(epoch uint64, offset int64) (*CommitPoint, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if epoch != w.epoch {
		return nil, ErrStaleEpoch
	}
	if offset < w.base {
		return nil, nil
	}
	record, ok := w.records[offset]
	if !ok {
		return nil, ErrUnknownDelivery
	}
	if !record.acked {
		record.acked = true
		w.records[offset] = record
	}
	var last int64
	var lastLeaderEpoch int32
	advanced := false
	for len(w.order) > 0 {
		offset := w.order[0]
		next := w.records[offset]
		if !next.acked {
			break
		}
		delete(w.records, offset)
		w.order = w.order[1:]
		w.bytes -= next.bytes
		last = offset
		lastLeaderEpoch = next.leaderEpoch
		w.base = offset + 1
		advanced = true
	}
	if !advanced {
		return nil, nil
	}
	return &CommitPoint{Topic: w.topic, Partition: w.partition, RecordOffset: last, NextOffset: last + 1, LeaderEpoch: lastLeaderEpoch}, nil
}

// ResetEpoch invalidates old tokens and clears all in-flight state.
func (w *PartitionAckWindow) ResetEpoch(epoch uint64, nextOffset int64) error {
	if nextOffset < 0 {
		return errors.New("negative next offset")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if epoch <= w.epoch {
		return ErrStaleEpoch
	}
	w.epoch, w.base, w.bytes, w.records, w.order = epoch, nextOffset, 0, map[int64]windowRecord{}, nil
	return nil
}

func (w *PartitionAckWindow) Pending() (records int, bytes int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.records), w.bytes
}

func (w *PartitionAckWindow) DeadlineState(now time.Time) DeadlineState {
	w.mu.Lock()
	defer w.mu.Unlock()
	var state DeadlineState
	for _, record := range w.records {
		if record.deadline.IsZero() {
			continue
		}
		if state.Earliest.IsZero() || record.deadline.Before(state.Earliest) {
			state.Earliest = record.deadline
		}
		if !now.Before(record.deadline) {
			state.ExpiredCount++
		}
	}
	return state
}

// Expired returns an ordered snapshot of delivered records whose acknowledgement
// deadline has elapsed. Mutating the returned slice does not affect the window.
func (w *PartitionAckWindow) Expired(now time.Time) []DeliveredRecord {
	w.mu.Lock()
	defer w.mu.Unlock()
	result := make([]DeliveredRecord, 0)
	for _, offset := range w.order {
		record := w.records[offset]
		if !record.acked && !record.deadline.IsZero() && !now.Before(record.deadline) {
			result = append(result, DeliveredRecord{Offset: offset, LeaderEpoch: record.leaderEpoch, Bytes: record.bytes, Deadline: record.deadline})
		}
	}
	return result
}

func (w *PartitionAckWindow) Epoch() uint64     { w.mu.Lock(); defer w.mu.Unlock(); return w.epoch }
func (w *PartitionAckWindow) NextOffset() int64 { w.mu.Lock(); defer w.mu.Unlock(); return w.base }

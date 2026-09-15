package kafka

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"sync/atomic"
)

const defaultStatusPartitionLimit = 128

// ExternalAckMetrics contains controller-wide counters only. Deliberately no
// topic, partition, token, or message identifiers are used as metric labels.
type ExternalAckMetrics struct {
	delivered       atomic.Uint64
	capacityRejects atomic.Uint64
	ackApplied      atomic.Uint64
	ackDuplicate    atomic.Uint64
	ackInvalid      atomic.Uint64
	ackStale        atomic.Uint64
	ackExpired      atomic.Uint64
	ackUnavailable  atomic.Uint64
	commitAttempts  atomic.Uint64
	commitFailures  atomic.Uint64
}

type ExternalAckMetricsSnapshot struct {
	Delivered       uint64 `json:"delivered"`
	CapacityRejects uint64 `json:"capacity_rejects"`
	AckApplied      uint64 `json:"ack_applied"`
	AckDuplicate    uint64 `json:"ack_duplicate"`
	AckInvalid      uint64 `json:"ack_invalid"`
	AckStale        uint64 `json:"ack_stale"`
	AckExpired      uint64 `json:"ack_expired"`
	AckUnavailable  uint64 `json:"ack_unavailable"`
	CommitAttempts  uint64 `json:"commit_attempts"`
	CommitFailures  uint64 `json:"commit_failures"`
}

func (m *ExternalAckMetrics) Snapshot() ExternalAckMetricsSnapshot {
	if m == nil {
		return ExternalAckMetricsSnapshot{}
	}
	return ExternalAckMetricsSnapshot{
		Delivered: m.delivered.Load(), CapacityRejects: m.capacityRejects.Load(),
		AckApplied: m.ackApplied.Load(), AckDuplicate: m.ackDuplicate.Load(),
		AckInvalid: m.ackInvalid.Load(), AckStale: m.ackStale.Load(),
		AckExpired: m.ackExpired.Load(), AckUnavailable: m.ackUnavailable.Load(),
		CommitAttempts: m.commitAttempts.Load(), CommitFailures: m.commitFailures.Load(),
	}
}

func (m *ExternalAckMetrics) observeResults(results []AckResult) {
	if m == nil {
		return
	}
	for _, result := range results {
		switch result.Disposition {
		case AckApplied:
			m.ackApplied.Add(1)
		case AckDuplicate:
			m.ackDuplicate.Add(1)
		case AckInvalid:
			m.ackInvalid.Add(1)
		case AckStale:
			m.ackStale.Add(1)
		case AckExpired:
			m.ackExpired.Add(1)
		case AckUnavailable:
			m.ackUnavailable.Add(1)
		}
	}
}

type ExternalAckPartitionStatus struct {
	Topic         string `json:"topic"`
	Partition     int32  `json:"partition"`
	Epoch         uint64 `json:"epoch"`
	NextOffset    int64  `json:"next_offset"`
	InFlight      int    `json:"in_flight"`
	InFlightBytes int64  `json:"in_flight_bytes"`
	PendingCommit bool   `json:"pending_commit"`
	Paused        bool   `json:"paused"`
}

type ExternalAckStatus struct {
	APIID               string                       `json:"api_id"`
	StreamID            string                       `json:"stream_id"`
	ComponentID         string                       `json:"component_id"`
	ClusterIDHash       string                       `json:"cluster_id_hash"`
	ReplayGeneration    string                       `json:"replay_generation"`
	Closed              bool                         `json:"closed"`
	InFlight            int                          `json:"in_flight"`
	InFlightBytes       int64                        `json:"in_flight_bytes"`
	PendingCommits      int                          `json:"pending_commits"`
	Partitions          []ExternalAckPartitionStatus `json:"partitions"`
	TruncatedPartitions int                          `json:"truncated_partitions"`
	Metrics             ExternalAckMetricsSnapshot   `json:"metrics"`
}

// StatusSnapshot returns a consistent, bounded view of controller state. A
// non-positive limit uses the safe default; callers cannot request an
// unbounded partition list.
func (c *ExternalAckController) StatusSnapshot(partitionLimit int) ExternalAckStatus {
	if partitionLimit <= 0 || partitionLimit > defaultStatusPartitionLimit {
		partitionLimit = defaultStatusPartitionLimit
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	status := ExternalAckStatus{
		APIID: c.key.APIID, StreamID: c.key.StreamID, ComponentID: c.key.ComponentID,
		ClusterIDHash: hashStatusIdentity(c.clusterID), ReplayGeneration: c.replayID,
		Closed: c.closed, InFlight: c.totalRecords, InFlightBytes: c.totalBytes,
		PendingCommits: len(c.pending), Metrics: c.metrics.Snapshot(),
	}
	partitions := make([]topicPartition, 0, len(c.windows))
	for tp := range c.windows {
		partitions = append(partitions, tp)
	}
	sort.Slice(partitions, func(i, j int) bool {
		if partitions[i].topic == partitions[j].topic {
			return partitions[i].partition < partitions[j].partition
		}
		return partitions[i].topic < partitions[j].topic
	})
	status.TruncatedPartitions = len(partitions) - min(len(partitions), partitionLimit)
	for _, tp := range partitions[:min(len(partitions), partitionLimit)] {
		window := c.windows[tp]
		records, bytes := window.Pending()
		status.Partitions = append(status.Partitions, ExternalAckPartitionStatus{
			Topic: tp.topic, Partition: tp.partition, Epoch: window.Epoch(),
			NextOffset: window.NextOffset(), InFlight: records, InFlightBytes: bytes,
			PendingCommit: c.pending[tp] != nil, Paused: c.shouldPauseLocked(tp, window),
		})
	}
	return status
}

func hashStatusIdentity(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

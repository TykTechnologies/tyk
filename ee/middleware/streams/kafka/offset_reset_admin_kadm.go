package kafka

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
)

type kadmOffsetClient interface {
	DescribeGroups(context.Context, ...string) (kadm.DescribedGroups, error)
	FetchOffsets(context.Context, string) (kadm.OffsetResponses, error)
	ListStartOffsets(context.Context, ...string) (kadm.ListedOffsets, error)
	ListEndOffsets(context.Context, ...string) (kadm.ListedOffsets, error)
	ListOffsetsAfterMilli(context.Context, int64, ...string) (kadm.ListedOffsets, error)
	CommitOffsets(context.Context, string, kadm.Offsets) (kadm.OffsetResponses, error)
}

// KadmOffsetResetAdmin adapts the production franz-go administration client
// to OffsetResetAdmin. The underlying kgo.Client lifecycle remains owned by
// the connector; this adapter never closes it.
type KadmOffsetResetAdmin struct {
	client kadmOffsetClient
}

var _ OffsetResetAdmin = (*KadmOffsetResetAdmin)(nil)

func NewKadmOffsetResetAdmin(client *kgo.Client) (*KadmOffsetResetAdmin, error) {
	if client == nil {
		return nil, errors.New("nil kafka client")
	}
	return &KadmOffsetResetAdmin{client: kadm.NewClient(client)}, nil
}

func newKadmOffsetResetAdmin(client kadmOffsetClient) *KadmOffsetResetAdmin {
	return &KadmOffsetResetAdmin{client: client}
}

func (a *KadmOffsetResetAdmin) DescribeGroup(ctx context.Context, group string) (GroupDescription, error) {
	if a == nil || a.client == nil {
		return GroupDescription{}, errors.New("nil kadm client")
	}
	groups, err := a.client.DescribeGroups(ctx, group)
	if err != nil {
		return GroupDescription{}, err
	}
	described, ok := groups[group]
	if !ok {
		return GroupDescription{}, fmt.Errorf("group %q missing from describe response", group)
	}
	if described.Err != nil {
		return GroupDescription{}, described.Err
	}
	members := make([]string, 0, len(described.Members))
	for _, member := range described.Members {
		identity := member.MemberID
		if member.InstanceID != nil {
			identity = *member.InstanceID
		}
		members = append(members, identity)
	}
	return GroupDescription{State: described.State, Members: members}, nil
}

func (a *KadmOffsetResetAdmin) FetchGroupOffsets(ctx context.Context, group string, partitions []TopicPartition) (map[TopicPartition]int64, error) {
	responses, err := a.client.FetchOffsets(ctx, group)
	if err != nil {
		return nil, err
	}
	result := make(map[TopicPartition]int64, len(partitions))
	for _, partition := range uniquePartitions(partitions) {
		response, ok := responses.Lookup(partition.Topic, partition.Partition)
		if !ok {
			// An absent entry is an uncommitted partition, represented by absence
			// so the controller can expose current offset -1.
			continue
		}
		if response.Err != nil {
			return nil, fmt.Errorf("fetch offset for %s/%d: %w", partition.Topic, partition.Partition, response.Err)
		}
		result[partition] = response.At
	}
	return result, nil
}

func (a *KadmOffsetResetAdmin) FetchLogBounds(ctx context.Context, partitions []TopicPartition) (map[TopicPartition]LogBounds, error) {
	partitions = uniquePartitions(partitions)
	topics := partitionTopics(partitions)
	starts, err := a.client.ListStartOffsets(ctx, topics...)
	if err != nil {
		return nil, err
	}
	ends, err := a.client.ListEndOffsets(ctx, topics...)
	if err != nil {
		return nil, err
	}
	result := make(map[TopicPartition]LogBounds, len(partitions))
	for _, partition := range partitions {
		start, startOK := starts.Lookup(partition.Topic, partition.Partition)
		end, endOK := ends.Lookup(partition.Topic, partition.Partition)
		if !startOK || !endOK {
			return nil, fmt.Errorf("log bounds missing for %s/%d", partition.Topic, partition.Partition)
		}
		if start.Err != nil {
			return nil, fmt.Errorf("log start for %s/%d: %w", partition.Topic, partition.Partition, start.Err)
		}
		if end.Err != nil {
			return nil, fmt.Errorf("log end for %s/%d: %w", partition.Topic, partition.Partition, end.Err)
		}
		result[partition] = LogBounds{Start: start.Offset, End: end.Offset}
	}
	return result, nil
}

func (a *KadmOffsetResetAdmin) ResolveTimestamps(ctx context.Context, requested map[TopicPartition]int64) (map[TopicPartition]TimestampOffset, error) {
	byTimestamp := make(map[int64][]TopicPartition)
	for partition, timestamp := range requested {
		byTimestamp[timestamp] = append(byTimestamp[timestamp], partition)
	}
	result := make(map[TopicPartition]TimestampOffset, len(requested))
	for timestamp, partitions := range byTimestamp {
		listed, err := a.client.ListOffsetsAfterMilli(ctx, timestamp, partitionTopics(partitions)...)
		if err != nil {
			return nil, err
		}
		for _, partition := range partitions {
			offset, ok := listed.Lookup(partition.Topic, partition.Partition)
			if !ok {
				result[partition] = TimestampOffset{}
				continue
			}
			if offset.Err != nil {
				return nil, fmt.Errorf("timestamp offset for %s/%d: %w", partition.Topic, partition.Partition, offset.Err)
			}
			result[partition] = TimestampOffset{Offset: offset.Offset, Found: offset.Offset >= 0}
		}
	}
	return result, nil
}

func (a *KadmOffsetResetAdmin) AlterGroupOffsets(ctx context.Context, group string, desired map[TopicPartition]int64) (map[TopicPartition]error, error) {
	offsets := make(kadm.Offsets)
	for partition, offset := range desired {
		offsets.AddOffset(partition.Topic, partition.Partition, offset, -1)
	}
	responses, err := a.client.CommitOffsets(ctx, group, offsets)
	if err != nil {
		return nil, err
	}
	result := make(map[TopicPartition]error, len(desired))
	for partition := range desired {
		response, ok := responses.Lookup(partition.Topic, partition.Partition)
		if !ok {
			result[partition] = errors.New("partition missing from alter-offset response")
			continue
		}
		result[partition] = response.Err
	}
	return result, nil
}

func uniquePartitions(partitions []TopicPartition) []TopicPartition {
	seen := make(map[TopicPartition]struct{}, len(partitions))
	result := make([]TopicPartition, 0, len(partitions))
	for _, partition := range partitions {
		if _, ok := seen[partition]; ok {
			continue
		}
		seen[partition] = struct{}{}
		result = append(result, partition)
	}
	return result
}

func partitionTopics(partitions []TopicPartition) []string {
	seen := make(map[string]struct{}, len(partitions))
	for _, partition := range partitions {
		seen[partition.Topic] = struct{}{}
	}
	topics := make([]string, 0, len(seen))
	for topic := range seen {
		topics = append(topics, topic)
	}
	sort.Strings(topics)
	return topics
}

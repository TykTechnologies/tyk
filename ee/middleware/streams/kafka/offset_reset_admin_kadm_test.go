package kafka

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/kafka"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
)

type fakeKadmOffsetClient struct {
	described       kadm.DescribedGroups
	describeErr     error
	fetched         kadm.OffsetResponses
	fetchErr        error
	starts          kadm.ListedOffsets
	startErr        error
	ends            kadm.ListedOffsets
	endErr          error
	byTimestamp     map[int64]kadm.ListedOffsets
	timestampErr    error
	timestampsAsked []int64
	committed       kadm.OffsetResponses
	commitErr       error
	commitInput     kadm.Offsets
}

func (f *fakeKadmOffsetClient) DescribeGroups(context.Context, ...string) (kadm.DescribedGroups, error) {
	return f.described, f.describeErr
}

func (f *fakeKadmOffsetClient) FetchOffsets(context.Context, string) (kadm.OffsetResponses, error) {
	return f.fetched, f.fetchErr
}

func (f *fakeKadmOffsetClient) ListStartOffsets(context.Context, ...string) (kadm.ListedOffsets, error) {
	return f.starts, f.startErr
}

func (f *fakeKadmOffsetClient) ListEndOffsets(context.Context, ...string) (kadm.ListedOffsets, error) {
	return f.ends, f.endErr
}

func (f *fakeKadmOffsetClient) ListOffsetsAfterMilli(_ context.Context, timestamp int64, _ ...string) (kadm.ListedOffsets, error) {
	f.timestampsAsked = append(f.timestampsAsked, timestamp)
	return f.byTimestamp[timestamp], f.timestampErr
}

func (f *fakeKadmOffsetClient) CommitOffsets(_ context.Context, _ string, offsets kadm.Offsets) (kadm.OffsetResponses, error) {
	f.commitInput = offsets
	return f.committed, f.commitErr
}

func TestKadmOffsetResetAdminMapsOperations(t *testing.T) {
	one := TopicPartition{Topic: "one", Partition: 0}
	two := TopicPartition{Topic: "two", Partition: 2}
	instance := "instance-1"
	client := &fakeKadmOffsetClient{
		described: kadm.DescribedGroups{"group": {
			Group: "group", State: "Empty",
			Members: []kadm.DescribedGroupMember{{MemberID: "member-1"}, {MemberID: "member-2", InstanceID: &instance}},
		}},
		fetched: offsetResponses(
			kadm.OffsetResponse{Offset: kadm.Offset{Topic: one.Topic, Partition: one.Partition, At: 12}},
		),
		starts: listedOffsets(
			kadm.ListedOffset{Topic: one.Topic, Partition: one.Partition, Offset: 10},
			kadm.ListedOffset{Topic: two.Topic, Partition: two.Partition, Offset: 20},
		),
		ends: listedOffsets(
			kadm.ListedOffset{Topic: one.Topic, Partition: one.Partition, Offset: 100},
			kadm.ListedOffset{Topic: two.Topic, Partition: two.Partition, Offset: 200},
		),
		byTimestamp: map[int64]kadm.ListedOffsets{
			1000: listedOffsets(kadm.ListedOffset{Topic: one.Topic, Partition: one.Partition, Offset: 30}),
			2000: listedOffsets(kadm.ListedOffset{Topic: two.Topic, Partition: two.Partition, Offset: 40}),
		},
		committed: offsetResponses(
			kadm.OffsetResponse{Offset: kadm.Offset{Topic: one.Topic, Partition: one.Partition, At: 30}},
			kadm.OffsetResponse{Offset: kadm.Offset{Topic: two.Topic, Partition: two.Partition, At: 40}},
		),
	}
	admin := newKadmOffsetResetAdmin(client)

	description, err := admin.DescribeGroup(context.Background(), "group")
	require.NoError(t, err)
	assert.Equal(t, GroupDescription{State: "Empty", Members: []string{"member-1", "instance-1"}}, description)

	current, err := admin.FetchGroupOffsets(context.Background(), "group", []TopicPartition{one, two})
	require.NoError(t, err)
	assert.Equal(t, map[TopicPartition]int64{one: 12}, current, "uncommitted partitions remain absent")

	bounds, err := admin.FetchLogBounds(context.Background(), []TopicPartition{one, two, one})
	require.NoError(t, err)
	assert.Equal(t, LogBounds{Start: 10, End: 100}, bounds[one])
	assert.Equal(t, LogBounds{Start: 20, End: 200}, bounds[two])

	resolved, err := admin.ResolveTimestamps(context.Background(), map[TopicPartition]int64{one: 1000, two: 2000})
	require.NoError(t, err)
	assert.Equal(t, TimestampOffset{Offset: 30, Found: true}, resolved[one])
	assert.Equal(t, TimestampOffset{Offset: 40, Found: true}, resolved[two])
	assert.ElementsMatch(t, []int64{1000, 2000}, client.timestampsAsked, "different timestamps require separate Kafka requests")

	altered, err := admin.AlterGroupOffsets(context.Background(), "group", map[TopicPartition]int64{one: 30, two: 40})
	require.NoError(t, err)
	assert.NoError(t, altered[one])
	assert.NoError(t, altered[two])
	committedOne, ok := client.commitInput.Lookup(one.Topic, one.Partition)
	require.True(t, ok)
	assert.Equal(t, int64(30), committedOne.At)
}

func TestKadmOffsetResetAdminFailsClosedPerTarget(t *testing.T) {
	one := TopicPartition{Topic: "one", Partition: 0}
	two := TopicPartition{Topic: "two", Partition: 1}
	partitionErr := errors.New("partition unauthorized")
	client := &fakeKadmOffsetClient{committed: offsetResponses(
		kadm.OffsetResponse{Offset: kadm.Offset{Topic: one.Topic, Partition: one.Partition, At: 10}, Err: partitionErr},
	)}
	admin := newKadmOffsetResetAdmin(client)
	results, err := admin.AlterGroupOffsets(context.Background(), "group", map[TopicPartition]int64{one: 10, two: 20})
	require.NoError(t, err)
	assert.ErrorIs(t, results[one], partitionErr)
	assert.Error(t, results[two], "a missing broker response must not be treated as success")
}

func TestKadmOffsetResetAdminRejectsMissingAndPartitionErrors(t *testing.T) {
	partition := TopicPartition{Topic: "one", Partition: 0}
	partitionErr := errors.New("leader unavailable")
	tests := []struct {
		name   string
		client *fakeKadmOffsetClient
		call   func(*KadmOffsetResetAdmin) error
	}{
		{"missing group", &fakeKadmOffsetClient{described: kadm.DescribedGroups{}}, func(admin *KadmOffsetResetAdmin) error {
			_, err := admin.DescribeGroup(context.Background(), "group")
			return err
		}},
		{"group response error", &fakeKadmOffsetClient{described: kadm.DescribedGroups{"group": {Err: partitionErr}}}, func(admin *KadmOffsetResetAdmin) error {
			_, err := admin.DescribeGroup(context.Background(), "group")
			return err
		}},
		{"committed offset error", &fakeKadmOffsetClient{fetched: offsetResponses(kadm.OffsetResponse{Offset: kadm.Offset{Topic: partition.Topic, Partition: partition.Partition}, Err: partitionErr})}, func(admin *KadmOffsetResetAdmin) error {
			_, err := admin.FetchGroupOffsets(context.Background(), "group", []TopicPartition{partition})
			return err
		}},
		{"missing log bound", &fakeKadmOffsetClient{starts: listedOffsets(), ends: listedOffsets()}, func(admin *KadmOffsetResetAdmin) error {
			_, err := admin.FetchLogBounds(context.Background(), []TopicPartition{partition})
			return err
		}},
		{"timestamp partition error", &fakeKadmOffsetClient{byTimestamp: map[int64]kadm.ListedOffsets{1: listedOffsets(kadm.ListedOffset{Topic: partition.Topic, Partition: partition.Partition, Err: partitionErr})}}, func(admin *KadmOffsetResetAdmin) error {
			_, err := admin.ResolveTimestamps(context.Background(), map[TopicPartition]int64{partition: 1})
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Error(t, test.call(newKadmOffsetResetAdmin(test.client)))
		})
	}

	client := &fakeKadmOffsetClient{byTimestamp: map[int64]kadm.ListedOffsets{1: listedOffsets(kadm.ListedOffset{Topic: partition.Topic, Partition: partition.Partition, Offset: -1})}}
	resolved, err := newKadmOffsetResetAdmin(client).ResolveTimestamps(context.Background(), map[TopicPartition]int64{partition: 1})
	require.NoError(t, err)
	assert.False(t, resolved[partition].Found)
}

func TestKadmOffsetResetAdminRealKafka(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	container, err := kafka.Run(ctx, "confluentinc/confluent-local:7.5.0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, container.Terminate(context.Background())) })
	brokers, err := container.Brokers(ctx)
	require.NoError(t, err)

	client, err := kgo.NewClient(kgo.SeedBrokers(brokers...))
	require.NoError(t, err)
	t.Cleanup(client.Close)
	topic := fmt.Sprintf("reset-admin-%d", time.Now().UnixNano())
	created, err := kadm.NewClient(client).CreateTopics(ctx, 1, 1, nil, topic)
	require.NoError(t, err)
	require.NoError(t, created.Error())
	produced := &kgo.Record{Topic: topic, Value: []byte("event"), Timestamp: time.Now().Add(-time.Minute)}
	require.NoError(t, client.ProduceSync(ctx, produced).FirstErr())

	admin, err := NewKadmOffsetResetAdmin(client)
	require.NoError(t, err)
	partition := TopicPartition{Topic: topic, Partition: produced.Partition}
	bounds, err := admin.FetchLogBounds(ctx, []TopicPartition{partition})
	require.NoError(t, err)
	assert.Equal(t, int64(0), bounds[partition].Start)
	assert.Equal(t, produced.Offset+1, bounds[partition].End)
	resolved, err := admin.ResolveTimestamps(ctx, map[TopicPartition]int64{partition: produced.Timestamp.UnixMilli()})
	require.NoError(t, err)
	assert.Equal(t, produced.Offset, resolved[partition].Offset)

	group := fmt.Sprintf("reset-group-%d", time.Now().UnixNano())
	results, err := admin.AlterGroupOffsets(ctx, group, map[TopicPartition]int64{partition: produced.Offset + 1})
	require.NoError(t, err)
	require.NoError(t, results[partition])
	current, err := admin.FetchGroupOffsets(ctx, group, []TopicPartition{partition})
	require.NoError(t, err)
	assert.Equal(t, produced.Offset+1, current[partition])
	description, err := admin.DescribeGroup(ctx, group)
	require.NoError(t, err)
	assert.True(t, strings.EqualFold("empty", description.State))
	assert.Empty(t, description.Members)
}

func offsetResponses(responses ...kadm.OffsetResponse) kadm.OffsetResponses {
	result := make(kadm.OffsetResponses)
	for _, response := range responses {
		result.Add(response)
	}
	return result
}

func listedOffsets(offsets ...kadm.ListedOffset) kadm.ListedOffsets {
	result := make(kadm.ListedOffsets)
	for _, offset := range offsets {
		partitions := result[offset.Topic]
		if partitions == nil {
			partitions = make(map[int32]kadm.ListedOffset)
			result[offset.Topic] = partitions
		}
		partitions[offset.Partition] = offset
	}
	return result
}

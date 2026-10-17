package kafka

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeResetAdmin struct {
	group          GroupDescription
	groupErr       error
	current        map[TopicPartition]int64
	bounds         map[TopicPartition]LogBounds
	timestamps     map[TopicPartition]TimestampOffset
	alterErrors    map[TopicPartition]error
	alterErr       error
	alterCalls     int
	altered        map[TopicPartition]int64
	lastDesired    map[TopicPartition]int64
	verifyOverride map[TopicPartition]int64
	boundsErr      error
	timestampsErr  error
	currentErr     error
}

func (f *fakeResetAdmin) DescribeGroup(context.Context, string) (GroupDescription, error) {
	return f.group, f.groupErr
}

func (f *fakeResetAdmin) FetchGroupOffsets(_ context.Context, _ string, partitions []TopicPartition) (map[TopicPartition]int64, error) {
	if f.currentErr != nil {
		return nil, f.currentErr
	}
	result := make(map[TopicPartition]int64, len(partitions))
	source := f.current
	if f.alterCalls > 0 {
		source = f.altered
		if f.verifyOverride != nil {
			source = f.verifyOverride
		}
	}
	for _, partition := range partitions {
		result[partition] = source[partition]
	}
	return result, nil
}

func (f *fakeResetAdmin) FetchLogBounds(_ context.Context, partitions []TopicPartition) (map[TopicPartition]LogBounds, error) {
	if f.boundsErr != nil {
		return nil, f.boundsErr
	}
	result := make(map[TopicPartition]LogBounds, len(partitions))
	for _, partition := range partitions {
		if bound, ok := f.bounds[partition]; ok {
			result[partition] = bound
		}
	}
	return result, nil
}

func (f *fakeResetAdmin) ResolveTimestamps(_ context.Context, requested map[TopicPartition]int64) (map[TopicPartition]TimestampOffset, error) {
	if f.timestampsErr != nil {
		return nil, f.timestampsErr
	}
	result := make(map[TopicPartition]TimestampOffset, len(requested))
	for partition := range requested {
		if offset, ok := f.timestamps[partition]; ok {
			result[partition] = offset
		}
	}
	return result, nil
}

func TestLocalOffsetResetControllerAdminFailuresAreUnavailable(t *testing.T) {
	controller, admin, _, _ := newResetFixture(t)
	offset := int64(12)
	timestamp := int64(1_700_000_000_000)
	base := ResetPlanRequest{ConsumerGroup: "vinci", Reason: "recovery", Targets: []ResetTarget{{Topic: "employees.eu", Partition: 0, Offset: &offset}}}

	for _, tc := range []struct {
		name    string
		prepare func()
		request ResetPlanRequest
	}{
		{"describe", func() { admin.groupErr = errors.New("describe unavailable") }, base},
		{"bounds", func() { admin.groupErr = nil; admin.boundsErr = errors.New("bounds unavailable") }, base},
		{"timestamps", func() { admin.boundsErr = nil; admin.timestampsErr = errors.New("timestamp unavailable") }, ResetPlanRequest{ConsumerGroup: "vinci", Reason: "recovery", Targets: []ResetTarget{{Topic: "employees.eu", Partition: 0, TimestampMS: &timestamp}}}},
		{"offsets", func() { admin.timestampsErr = nil; admin.currentErr = errors.New("offsets unavailable") }, base},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(func() { admin.groupErr, admin.boundsErr, admin.timestampsErr, admin.currentErr = nil, nil, nil, nil })
			tc.prepare()
			_, err := controller.PlanReset(context.Background(), tc.request)
			var control *ControlError
			require.ErrorAs(t, err, &control)
			require.Equal(t, http.StatusServiceUnavailable, control.Status)
		})
	}
}

func TestLocalOffsetResetControllerRejectsAllMalformedTargets(t *testing.T) {
	controller, _, _, _ := newResetFixture(t)
	zero, negative := int64(0), int64(-1)
	for _, request := range []ResetPlanRequest{
		{ConsumerGroup: "other", Reason: "x", Targets: []ResetTarget{{Topic: "employees.eu", Partition: 0, Offset: &zero}}},
		{ConsumerGroup: "vinci", Targets: []ResetTarget{{Topic: "employees.eu", Partition: 0, Offset: &zero}}},
		{ConsumerGroup: "vinci", Reason: "x"},
		{ConsumerGroup: "vinci", Reason: "x", Targets: []ResetTarget{{Topic: "unknown", Partition: 0, Offset: &zero}}},
		{ConsumerGroup: "vinci", Reason: "x", Targets: []ResetTarget{{Topic: "employees.eu", Partition: -1, Offset: &zero}}},
		{ConsumerGroup: "vinci", Reason: "x", Targets: []ResetTarget{{Topic: "employees.eu", Partition: 0}}},
		{ConsumerGroup: "vinci", Reason: "x", Targets: []ResetTarget{{Topic: "employees.eu", Partition: 0, Offset: &zero, TimestampMS: &zero}}},
		{ConsumerGroup: "vinci", Reason: "x", Targets: []ResetTarget{{Topic: "employees.eu", Partition: 0, Offset: &negative}}},
		{ConsumerGroup: "vinci", Reason: "x", Targets: []ResetTarget{{Topic: "employees.eu", Partition: 0, Offset: &zero}, {Topic: "employees.eu", Partition: 0, Offset: &zero}}},
	} {
		_, err := controller.PlanReset(context.Background(), request)
		var control *ControlError
		require.ErrorAs(t, err, &control)
		require.Equal(t, http.StatusBadRequest, control.Status)
	}
}

func (f *fakeResetAdmin) AlterGroupOffsets(_ context.Context, _ string, desired map[TopicPartition]int64) (map[TopicPartition]error, error) {
	f.alterCalls++
	f.lastDesired = make(map[TopicPartition]int64, len(desired))
	for partition, offset := range desired {
		f.lastDesired[partition] = offset
	}
	f.altered = make(map[TopicPartition]int64, len(f.current)+len(desired))
	for partition, offset := range f.current {
		f.altered[partition] = offset
	}
	results := make(map[TopicPartition]error, len(desired))
	for partition, offset := range desired {
		results[partition] = f.alterErrors[partition]
		if f.alterErrors[partition] == nil && f.alterErr == nil {
			f.altered[partition] = offset
		} else {
			f.altered[partition] = f.current[partition]
		}
	}
	return results, f.alterErr
}

func TestLocalOffsetResetControllerResumesStoredRunningExecution(t *testing.T) {
	controller, admin, store, _ := newResetFixture(t)
	one := ResolvedResetTarget{Topic: "employees.eu", Partition: 0, CurrentOffset: 80, TargetOffset: 25}
	two := ResolvedResetTarget{Topic: "employees.us", Partition: 2, CurrentOffset: 90, TargetOffset: 120}
	plan := ResetPlan{ID: "recover-plan", ExpiresAt: time.Unix(1_800_000_030, 0).UTC(), Targets: []ResolvedResetTarget{one, two}}
	require.NoError(t, store.PutPlan(context.Background(), StoredResetPlan{Plan: plan, ConsumerGroup: "vinci", Targets: plan.Targets}))
	require.NoError(t, store.PutExecution(context.Background(), StoredResetExecution{
		Execution: ResetExecution{ID: "original-execution", Status: "running"}, PlanID: plan.ID,
		Targets: []ResetTargetState{{Target: one, Applied: true}, {Target: two}},
	}))
	admin.current[TopicPartition{Topic: one.Topic, Partition: one.Partition}] = one.TargetOffset

	execution, err := controller.ExecuteReset(context.Background(), ResetExecuteRequest{PlanID: plan.ID})
	require.NoError(t, err)
	assert.Equal(t, "original-execution", execution.ID)
	assert.Equal(t, "completed", execution.Status)
	assert.Equal(t, 1, admin.alterCalls)
	_, alteredAlreadyApplied := admin.lastDesired[TopicPartition{Topic: one.Topic, Partition: one.Partition}]
	assert.False(t, alteredAlreadyApplied, "controller does not reapply a durably recorded target")
}

func newResetFixture(t *testing.T) (*LocalOffsetResetController, *fakeResetAdmin, *InMemoryResetStateStore, *time.Time) {
	t.Helper()
	one := TopicPartition{Topic: "employees.eu", Partition: 0}
	two := TopicPartition{Topic: "employees.us", Partition: 2}
	admin := &fakeResetAdmin{
		group:      GroupDescription{State: "Empty"},
		current:    map[TopicPartition]int64{one: 80, two: 90},
		bounds:     map[TopicPartition]LogBounds{one: {Start: 10, End: 100}, two: {Start: 20, End: 200}},
		timestamps: map[TopicPartition]TimestampOffset{two: {Offset: 120, Found: true}},
	}
	store := NewInMemoryResetStateStore()
	now := time.Unix(1_800_000_000, 0).UTC()
	controller, err := NewLocalOffsetResetController(LocalOffsetResetControllerConfig{
		ConsumerGroup: "vinci", Topics: []string{one.Topic, two.Topic}, PlanTTL: time.Minute,
		Admin: admin, Store: store, Now: func() time.Time { return now },
	})
	require.NoError(t, err)
	return controller, admin, store, &now
}

func TestLocalOffsetResetControllerPlanAndExecute(t *testing.T) {
	controller, admin, store, _ := newResetFixture(t)
	offset := int64(25)
	timestamp := int64(1_780_000_000_000)
	plan, err := controller.PlanReset(context.Background(), ResetPlanRequest{
		ConsumerGroup: "vinci", Reason: "replay ETL",
		Targets: []ResetTarget{
			{Topic: "employees.us", Partition: 2, TimestampMS: &timestamp},
			{Topic: "employees.eu", Partition: 0, Offset: &offset},
		},
	})
	require.NoError(t, err)
	require.Len(t, plan.Targets, 2)
	assert.Equal(t, "employees.eu", plan.Targets[0].Topic, "plans are deterministic")
	assert.Equal(t, int64(25), plan.Targets[0].TargetOffset)
	assert.Equal(t, int64(120), plan.Targets[1].TargetOffset)

	execution, err := controller.ExecuteReset(context.Background(), ResetExecuteRequest{PlanID: plan.ID})
	require.NoError(t, err)
	assert.Equal(t, "completed", execution.Status)
	assert.Equal(t, 1, admin.alterCalls)

	again, err := controller.ExecuteReset(context.Background(), ResetExecuteRequest{PlanID: plan.ID})
	require.NoError(t, err)
	assert.Equal(t, execution, again)
	assert.Equal(t, 1, admin.alterCalls, "completed execution is idempotent")

	stored, ok, err := store.GetExecution(context.Background(), plan.ID)
	require.NoError(t, err)
	require.True(t, ok)
	for _, target := range stored.Targets {
		assert.True(t, target.Applied)
		assert.True(t, target.Verified)
		assert.False(t, target.Failed)
	}
}

func TestLocalOffsetResetControllerRejectsActiveOrUnknownMembers(t *testing.T) {
	for name, description := range map[string]GroupDescription{
		"active Tyk":     {State: "Stable", Members: []string{"tyk-1"}},
		"non-Tyk member": {State: "Stable", Members: []string{"foreign-consumer"}},
		"nonempty state": {State: "PreparingRebalance"},
	} {
		t.Run(name, func(t *testing.T) {
			controller, admin, _, _ := newResetFixture(t)
			admin.group = description
			offset := int64(25)
			_, err := controller.PlanReset(context.Background(), ResetPlanRequest{
				ConsumerGroup: "vinci", Reason: "test",
				Targets: []ResetTarget{{Topic: "employees.eu", Partition: 0, Offset: &offset}},
			})
			assertControlStatus(t, err, http.StatusConflict)
		})
	}
}

func TestLocalOffsetResetControllerValidatesScopeResolutionAndBounds(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*fakeResetAdmin)
		group  string
		target ResetTarget
	}{
		{name: "wrong group", group: "other", target: offsetTarget("employees.eu", 0, 25)},
		{name: "unknown topic", group: "vinci", target: offsetTarget("other", 0, 25)},
		{name: "below log start", group: "vinci", target: offsetTarget("employees.eu", 0, 9)},
		{name: "above log end", group: "vinci", target: offsetTarget("employees.eu", 0, 101)},
		{name: "timestamp has no offset", group: "vinci", target: timestampTarget("employees.eu", 0, 100)},
		{name: "resolved timestamp outside bounds", group: "vinci", target: timestampTarget("employees.us", 2, 100), mutate: func(admin *fakeResetAdmin) {
			admin.timestamps[TopicPartition{Topic: "employees.us", Partition: 2}] = TimestampOffset{Offset: 201, Found: true}
		}},
		{name: "missing bounds", group: "vinci", target: offsetTarget("employees.eu", 0, 25), mutate: func(admin *fakeResetAdmin) {
			delete(admin.bounds, TopicPartition{Topic: "employees.eu", Partition: 0})
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			controller, admin, _, _ := newResetFixture(t)
			if test.mutate != nil {
				test.mutate(admin)
			}
			_, err := controller.PlanReset(context.Background(), ResetPlanRequest{
				ConsumerGroup: test.group, Reason: "test", Targets: []ResetTarget{test.target},
			})
			assertControlStatus(t, err, http.StatusBadRequest)
		})
	}

	controller, _, _, _ := newResetFixture(t)
	for _, valid := range []int64{10, 100} {
		_, err := controller.PlanReset(context.Background(), ResetPlanRequest{
			ConsumerGroup: "vinci", Reason: "boundary",
			Targets: []ResetTarget{offsetTarget("employees.eu", 0, valid)},
		})
		assert.NoError(t, err, "log start and end are valid reset offsets")
	}
}

func TestLocalOffsetResetControllerExpiredAndMissingPlans(t *testing.T) {
	controller, _, _, now := newResetFixture(t)
	offset := int64(25)
	plan, err := controller.PlanReset(context.Background(), ResetPlanRequest{
		ConsumerGroup: "vinci", Reason: "test", Targets: []ResetTarget{{Topic: "employees.eu", Partition: 0, Offset: &offset}},
	})
	require.NoError(t, err)
	*now = now.Add(time.Minute)
	_, err = controller.ExecuteReset(context.Background(), ResetExecuteRequest{PlanID: plan.ID})
	assertControlStatus(t, err, http.StatusGone)
	_, err = controller.ExecuteReset(context.Background(), ResetExecuteRequest{PlanID: "missing"})
	assertControlStatus(t, err, http.StatusNotFound)
}

func TestLocalOffsetResetControllerPersistsPartialFailure(t *testing.T) {
	controller, admin, store, _ := newResetFixture(t)
	one := TopicPartition{Topic: "employees.eu", Partition: 0}
	two := TopicPartition{Topic: "employees.us", Partition: 2}
	admin.alterErrors = map[TopicPartition]error{two: errors.New("not leader")}
	firstOffset, secondOffset := int64(25), int64(120)
	plan, err := controller.PlanReset(context.Background(), ResetPlanRequest{
		ConsumerGroup: "vinci", Reason: "test",
		Targets: []ResetTarget{
			{Topic: one.Topic, Partition: one.Partition, Offset: &firstOffset},
			{Topic: two.Topic, Partition: two.Partition, Offset: &secondOffset},
		},
	})
	require.NoError(t, err)
	execution, err := controller.ExecuteReset(context.Background(), ResetExecuteRequest{PlanID: plan.ID})
	require.NoError(t, err)
	assert.Equal(t, "partial_failed", execution.Status)
	stored, ok, err := store.GetExecution(context.Background(), plan.ID)
	require.NoError(t, err)
	require.True(t, ok)
	assert.True(t, stored.Targets[0].Verified)
	assert.True(t, stored.Targets[1].Failed)

	delete(admin.alterErrors, two)
	retried, err := controller.ExecuteReset(context.Background(), ResetExecuteRequest{PlanID: plan.ID})
	require.NoError(t, err)
	assert.Equal(t, "completed", retried.Status)
	assert.Equal(t, 2, admin.alterCalls, "retry resumes only the previously failed target")
	_, alteredAlreadyApplied := admin.lastDesired[one]
	assert.False(t, alteredAlreadyApplied)
}

func TestLocalOffsetResetControllerDetectsVerificationMismatch(t *testing.T) {
	controller, admin, store, _ := newResetFixture(t)
	partition := TopicPartition{Topic: "employees.eu", Partition: 0}
	admin.verifyOverride = map[TopicPartition]int64{partition: 24}
	offset := int64(25)
	plan, err := controller.PlanReset(context.Background(), ResetPlanRequest{
		ConsumerGroup: "vinci", Reason: "test", Targets: []ResetTarget{{Topic: partition.Topic, Partition: partition.Partition, Offset: &offset}},
	})
	require.NoError(t, err)
	execution, err := controller.ExecuteReset(context.Background(), ResetExecuteRequest{PlanID: plan.ID})
	require.NoError(t, err)
	assert.Equal(t, "partial_failed", execution.Status)
	stored, _, _ := store.GetExecution(context.Background(), plan.ID)
	assert.True(t, stored.Targets[0].Applied)
	assert.False(t, stored.Targets[0].Verified)
	assert.True(t, stored.Targets[0].Failed)
}

func TestLocalOffsetResetControllerRechecksEmptyGroupAtExecution(t *testing.T) {
	controller, admin, _, _ := newResetFixture(t)
	offset := int64(25)
	plan, err := controller.PlanReset(context.Background(), ResetPlanRequest{
		ConsumerGroup: "vinci", Reason: "test", Targets: []ResetTarget{{Topic: "employees.eu", Partition: 0, Offset: &offset}},
	})
	require.NoError(t, err)
	admin.group = GroupDescription{State: "Stable", Members: []string{"late-member"}}
	_, err = controller.ExecuteReset(context.Background(), ResetExecuteRequest{PlanID: plan.ID})
	assertControlStatus(t, err, http.StatusConflict)
	assert.Zero(t, admin.alterCalls)
}

func offsetTarget(topic string, partition int32, offset int64) ResetTarget {
	return ResetTarget{Topic: topic, Partition: partition, Offset: &offset}
}

func timestampTarget(topic string, partition int32, timestamp int64) ResetTarget {
	return ResetTarget{Topic: topic, Partition: partition, TimestampMS: &timestamp}
}

func assertControlStatus(t *testing.T, err error, status int) {
	t.Helper()
	var control *ControlError
	require.ErrorAs(t, err, &control)
	assert.Equal(t, status, control.Status)
}

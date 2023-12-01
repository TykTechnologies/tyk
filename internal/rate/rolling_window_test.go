//go:build unit
// +build unit

package rate_test

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/internal/rate"
	redis "github.com/go-redis/redis/v8"
	redismock "github.com/go-redis/redismock/v8"
	"github.com/stretchr/testify/assert"
)

func Test_GetRollingWindow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var (
		transactionOn        = false
		transactionOff       = true
		per            int64 = 60
		key                  = "test-key"
	)

	now := time.Now()
	wantErr := errors.New("Test error return")

	previousPeriod := now.Add(time.Duration(-1*per) * time.Second)
	previousVal := strconv.Itoa(int(previousPeriod.UnixNano()))

	expectPipeline := func(mock redismock.ClientMock, values []string, err error) {
		mock.ExpectZRemRangeByScore(key, "-inf", previousVal).SetVal(0)
		if err != nil {
			mock.ExpectZRange(key, 0, -1).SetErr(err)
		} else {
			mock.ExpectZRange(key, 0, -1).SetVal(values)
		}
	}

	expectTxPipeline := func(mock redismock.ClientMock, values []string, err error) {
		mock.ExpectTxPipeline()
		expectPipeline(mock, values, err)
		if err == nil {
			mock.ExpectTxPipelineExec()
		}
	}

	t.Run("no-transaction", func(t *testing.T) {
		tx := transactionOff
		expect := expectPipeline

		t.Run("value", func(t *testing.T) {
			conn, mock := redismock.NewClientMock()

			want := []string{"a", "b", "c"}
			expect(mock, want, nil)

			rl := rate.NewRollingWindow(conn)
			got, err := rl.GetRollingWindow(ctx, now, key, per, tx)

			assert.NoError(t, mock.ExpectationsWereMet())

			assert.NoError(t, err)
			assert.Equal(t, want, got)
		})

		t.Run("error", func(t *testing.T) {
			conn, mock := redismock.NewClientMock()

			want := []string{"a", "b", "c"}
			expect(mock, want, wantErr)

			rl := rate.NewRollingWindow(conn)
			got, err := rl.GetRollingWindow(ctx, now, key, per, tx)

			assert.NoError(t, mock.ExpectationsWereMet())
			assert.ErrorIs(t, err, wantErr)
			assert.Nil(t, got)
		})
	})

	t.Run("transaction", func(t *testing.T) {
		tx := transactionOn
		expect := expectTxPipeline

		t.Run("value", func(t *testing.T) {
			conn, mock := redismock.NewClientMock()

			want := []string{"a", "b", "c"}
			expect(mock, want, nil)

			rl := rate.NewRollingWindow(conn)
			got, err := rl.GetRollingWindow(ctx, now, key, per, tx)

			assert.NoError(t, mock.ExpectationsWereMet())
			assert.NoError(t, err)
			assert.Equal(t, want, got)
		})

		t.Run("error", func(t *testing.T) {
			conn, mock := redismock.NewClientMock()

			want := []string{"a", "b", "c"}
			expect(mock, want, wantErr)

			rl := rate.NewRollingWindow(conn)
			got, err := rl.GetRollingWindow(ctx, now, key, per, tx)

			assert.NoError(t, mock.ExpectationsWereMet())
			assert.ErrorIs(t, err, wantErr)
			assert.Nil(t, got)
		})
	})
}

func Test_SetRollingWindow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var (
		transactionOn        = false
		transactionOff       = true
		key                  = "test-key"
		per            int64 = 60

		perDuration time.Duration = time.Duration(per) * time.Second
	)

	now := time.Now()
	wantErr := errors.New("Test error return")
	previousPeriod := now.Add(time.Duration(-1*per) * time.Second)

	nowVal := strconv.Itoa(int(now.UnixNano()))
	previousVal := strconv.Itoa(int(previousPeriod.UnixNano()))

	expectPipeline := func(mock redismock.ClientMock, member string, values []string, err error) {
		mock.ExpectZRemRangeByScore(key, "-inf", previousVal).SetVal(0)

		if err != nil {
			mock.ExpectZRange(key, 0, -1).SetErr(err)
			return
		} else {
			mock.ExpectZRange(key, 0, -1).SetVal(values)
		}

		mock.ExpectZAdd(key, &redis.Z{
			Member: member,
			Score:  float64(now.UnixNano()),
		}).SetVal(1)

		mock.ExpectExpire(key, perDuration).SetVal(true)
	}

	expectTxPipeline := func(mock redismock.ClientMock, member string, values []string, err error) {
		mock.ExpectTxPipeline()
		expectPipeline(mock, member, values, err)
		if err == nil {
			mock.ExpectTxPipelineExec()
		}
	}

	t.Run("no-transaction", func(t *testing.T) {
		tx := transactionOff
		expect := expectPipeline

		t.Run("default", func(t *testing.T) {
			conn, mock := redismock.NewClientMock()

			want := []string{"a", "b", "c"}
			expect(mock, nowVal, want, nil)

			rl := rate.NewRollingWindow(conn)
			got, err := rl.SetRollingWindow(ctx, now, key, per, "-1", tx)

			assert.NoError(t, err)
			assert.Equal(t, want, got)
			assert.NoError(t, mock.ExpectationsWereMet())
		})

		t.Run("value", func(t *testing.T) {
			conn, mock := redismock.NewClientMock()

			want := []string{"a", "b", "c"}
			expect(mock, "123", want, nil)

			rl := rate.NewRollingWindow(conn)
			got, err := rl.SetRollingWindow(ctx, now, key, per, "123", tx)

			assert.NoError(t, err)
			assert.Equal(t, want, got)
			assert.NoError(t, mock.ExpectationsWereMet())
		})

		t.Run("error", func(t *testing.T) {
			conn, mock := redismock.NewClientMock()

			want := []string{"a", "b", "c"}
			expect(mock, "123", want, wantErr)

			rl := rate.NewRollingWindow(conn)
			got, err := rl.SetRollingWindow(ctx, now, key, per, "123", tx)

			assert.NoError(t, mock.ExpectationsWereMet())
			assert.ErrorIs(t, err, wantErr)
			assert.Nil(t, got)
		})
	})

	t.Run("transaction", func(t *testing.T) {
		tx := transactionOn
		expect := expectTxPipeline

		t.Run("default", func(t *testing.T) {
			conn, mock := redismock.NewClientMock()

			want := []string{"a", "b", "c"}
			expect(mock, nowVal, want, nil)

			rl := rate.NewRollingWindow(conn)
			got, err := rl.SetRollingWindow(ctx, now, key, per, "-1", tx)

			assert.NoError(t, err)
			assert.Equal(t, want, got)
			assert.NoError(t, mock.ExpectationsWereMet())
		})

		t.Run("value", func(t *testing.T) {
			conn, mock := redismock.NewClientMock()

			want := []string{"a", "b", "c"}
			expect(mock, "123", want, nil)

			rl := rate.NewRollingWindow(conn)
			got, err := rl.SetRollingWindow(ctx, now, key, per, "123", tx)

			assert.NoError(t, mock.ExpectationsWereMet())
			assert.NoError(t, err)
			assert.Equal(t, want, got)
		})

		t.Run("error", func(t *testing.T) {
			conn, mock := redismock.NewClientMock()

			want := []string{"a", "b", "c"}
			expect(mock, "123", want, wantErr)

			rl := rate.NewRollingWindow(conn)
			got, err := rl.SetRollingWindow(ctx, now, key, per, "123", tx)

			assert.NoError(t, mock.ExpectationsWereMet())
			assert.ErrorIs(t, err, wantErr)
			assert.Nil(t, got)
		})
	})
}

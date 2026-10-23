package rate

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/redis"
	"github.com/TykTechnologies/tyk/internal/uuid"
	"github.com/TykTechnologies/tyk/storage"
)

const testRequestCount int = 1000

// allowAll is a smoothing function that never blocks.
func allowAll(_ context.Context, _ string, _, _ int64) bool { return false }

// blockAtLimit mirrors the smoothing function built in gateway/session_manager.go limitRedis.
func blockAtLimit(_ context.Context, _ string, currentRate, maxAllowed int64) bool {
	return currentRate > maxAllowed-1
}

func connectRedis(tb testing.TB) redis.UniversalClient {
	tb.Helper()

	conf, err := config.New()
	require.NoError(tb, err)

	conn, err := storage.NewConnector(storage.DefaultConn, *conf)
	require.Nil(tb, err)

	var db redis.UniversalClient
	ok := conn.As(&db)
	require.True(tb, ok)

	tb.Cleanup(func() {
		_ = db.Close()
	})

	return db
}

func newKey(tb testing.TB, db redis.UniversalClient) string {
	tb.Helper()

	key := uuid.New()
	tb.Cleanup(func() { db.Del(context.Background(), key) })

	return key
}

type dummyClientProvider struct{}

func (*dummyClientProvider) Client() (redis.UniversalClient, error) {
	return nil, io.EOF
}

type SlidingLogSuite struct {
	suite.Suite

	db  redis.UniversalClient
	key string
}

func TestSlidingLog(t *testing.T) {
	suite.Run(t, new(SlidingLogSuite))
}

func (s *SlidingLogSuite) SetupSuite() {
	s.db = connectRedis(s.T())
}

func (s *SlidingLogSuite) SetupTest() {
	s.key = newKey(s.T(), s.db)
}

func (s *SlidingLogSuite) ctx() context.Context {
	return s.T().Context()
}

func (s *SlidingLogSuite) redisNow() time.Time {
	now, err := s.db.Time(s.ctx()).Result()
	s.Require().NoError(err)

	return now
}

// seed writes log entries the way the lua script does: nanosecond score and member.
func (s *SlidingLogSuite) seed(at ...time.Time) {
	for _, ts := range at {
		nano := ts.UnixNano()
		err := s.db.ZAdd(s.ctx(), s.key, redis.Z{Score: float64(nano), Member: strconv.FormatInt(nano, 10)}).Err()
		s.Require().NoError(err)
	}
}

func (s *SlidingLogSuite) TestSmoothingFnDecides() {
	rl := NewSlidingLogRedis(s.db, func(_ context.Context, k string, _ int64, maxAllowedRate int64) bool {
		s.Equal(s.key, k)
		s.Equal(int64(40), maxAllowedRate)
		return true
	})

	_, blocked, err := rl.Do(s.ctx(), s.key, 40, 10)
	s.Require().NoError(err)
	s.True(blocked)
}

func (s *SlidingLogSuite) TestConstructorErrors() {
	_, err := NewSlidingLog(nil, nil)
	s.ErrorIs(err, ErrRedisClientProvider)

	_, err = NewSlidingLog(&dummyClientProvider{}, nil)
	s.ErrorIs(err, io.EOF)
}

func (s *SlidingLogSuite) TestSuccessFlow() {
	rl := NewSlidingLogRedis(s.db, blockAtLimit)

	res, blocked, err := rl.Do(s.ctx(), s.key, 3, 10)
	s.Require().NoError(err)
	s.False(blocked)
	s.Equal(Stats{Count: 0, Limit: 3, Remaining: 2, Reset: 0}, res)

	res, blocked, err = rl.Do(s.ctx(), s.key, 3, 10)
	s.Require().NoError(err)
	s.False(blocked)
	s.Equal(Stats{Count: 1, Limit: 3, Remaining: 1, Reset: 0}, res)

	// last slot: reset is a full period from now
	res, blocked, err = rl.Do(s.ctx(), s.key, 3, 10)
	s.Require().NoError(err)
	s.False(blocked)
	s.Equal(2, res.Count)
	s.Equal(0, res.Remaining)
	s.Equal(10*time.Second, res.Reset)

	// over the limit: reset is when the oldest of the last 3 entries leaves the window
	res, blocked, err = rl.Do(s.ctx(), s.key, 3, 10)
	s.Require().NoError(err)
	s.True(blocked)
	s.Equal(3, res.Count)
	s.Equal(0, res.Remaining)
	s.InDelta(10, res.Reset.Seconds(), .1)

	ttl, err := s.db.TTL(s.ctx(), s.key).Result()
	s.Require().NoError(err)
	s.InDelta(float64(10), ttl.Seconds(), .1)
}

// TestTwoNodes covers TT-18135: two gateways share one key, the limit holds across
// both, and entries written earlier in the window count whatever the writing node's clock said.
func (s *SlidingLogSuite) TestTwoNodes() {
	const limit, per = int64(4), int64(300)

	now := s.redisNow()
	s.seed(
		now.Add(-301*time.Second), // outside the window, pruned
		now.Add(-295*time.Second), // node B, 4m55s ago by its clock
		now.Add(-294*time.Second),
	)

	nodeA := NewSlidingLogRedis(s.db, blockAtLimit)
	nodeB := NewSlidingLogRedis(s.db, blockAtLimit)

	res, blocked, err := nodeA.Do(s.ctx(), s.key, limit, per)
	s.Require().NoError(err)
	s.False(blocked)
	s.Equal(2, res.Count, "node A must still see both node B entries")
	s.Equal(1, res.Remaining)

	res, blocked, err = nodeB.Do(s.ctx(), s.key, limit, per)
	s.Require().NoError(err)
	s.False(blocked)
	s.Equal(3, res.Count)
	s.Equal(0, res.Remaining)

	res, blocked, err = nodeA.Do(s.ctx(), s.key, limit, per)
	s.Require().NoError(err)
	s.True(blocked, "limit %d exceeded, got count %d", limit, res.Count)
	s.Equal(4, res.Count)
	s.Equal(0, res.Remaining)
	s.InDelta(6, res.Reset.Seconds(), .1, "blocked hit is logged too, so the slot frees with the 4m54s old entry")
}

// TestScriptErrorBlocks checks that a failing script blocks and surfaces the error.
func (s *SlidingLogSuite) TestScriptErrorBlocks() {
	s.Require().NoError(s.db.Set(s.ctx(), s.key, "not a sorted set", 0).Err())

	rl := NewSlidingLogRedis(s.db, allowAll)

	res, blocked, err := rl.Do(s.ctx(), s.key, 3, 10)
	s.Error(err)
	s.True(blocked)
	s.Equal(NewEmptyStats(), res)
}

// memberCollision is the unique-member branch from sliding_log_add.lua with the
// timestamp injected, so benchmarks can force collisions.
var memberCollision = redis.NewScript(`
local key = KEYS[1]
local now_str = ARGV[1]
local member = now_str
if redis.call("ZADD", key, "NX", now_str, member) == 0 then
	local prefix = now_str:sub(1, -4)
	local seq = redis.call("ZCOUNT", key, now_str, now_str)
	member = prefix .. string.format("%03d", seq)
	if seq > 999 or redis.call("ZADD", key, "NX", now_str, member) == 0 then
		return redis.error_reply("sliding log full at " .. now_str)
	end
end
return member
`)

// TestMemberCollisionJump checks the ZCOUNT jump picks a free member in this
// microsecond with neighbours from other microseconds present.
func (s *SlidingLogSuite) TestMemberCollisionJump() {
	now := time.Now().UnixMicro() * 1000
	prefix := func(nano int64) string {
		str := strconv.FormatInt(nano, 10)
		return str[:len(str)-3]
	}
	add := func(score int64, member string) {
		s.Require().NoError(s.db.ZAdd(s.ctx(), s.key, redis.Z{Score: float64(score), Member: member}).Err())
	}

	// entries written by this script share their microsecond's score, so the count is exact
	add(now-1000, prefix(now-1000)+"999")
	add(now, prefix(now)+"000")
	add(now, prefix(now)+"001")
	add(now+1000, prefix(now+1000)+"000")

	nowStr := strconv.FormatInt(now, 10)

	member, err := memberCollision.Run(s.ctx(), s.db, []string{s.key}, nowStr).Text()
	s.Require().NoError(err)
	s.Equal(prefix(now)+"002", member)

	member, err = memberCollision.Run(s.ctx(), s.db, []string{s.key}, nowStr).Text()
	s.Require().NoError(err)
	s.Equal(prefix(now)+"003", member)

	// entries written by older gateways carry nanosecond scores; whether they
	// round onto this microsecond's score or not, the member must still be free
	add(now-500, strconv.FormatInt(now-500, 10))
	add(now+500, strconv.FormatInt(now+500, 10))

	member, err = memberCollision.Run(s.ctx(), s.db, []string{s.key}, nowStr).Text()
	s.Require().NoError(err)
	s.True(strings.HasPrefix(member, prefix(now)), member)

	count, err := s.db.ZCard(s.ctx(), s.key).Result()
	s.Require().NoError(err)
	s.Equal(int64(9), count)
}

func (s *SlidingLogSuite) TestParseSlidingLogAddReply() {
	good := []any{int64(2), int64(0), "1700000000000000000", "1700000000000005000", int64(1)}

	reply, err := parseSlidingLogAddReply(good)
	s.Require().NoError(err)
	s.Equal(slidingLogAddReply{count: 2, remaining: 0, earliestNano: 1700000000000000000, nowNano: 1700000000000005000, collisions: 1}, reply)

	for index := range 5 {
		s.Run("field "+strconv.Itoa(index)+" of wrong type", func() {
			bad := append([]any{}, good...)
			bad[index] = 3.14

			_, err := parseSlidingLogAddReply(bad)
			s.ErrorIs(err, ErrUnexpectedResponse)
			s.ErrorContains(err, "field "+strconv.Itoa(index))
		})
	}

	for _, index := range []int{2, 3} {
		s.Run("field "+strconv.Itoa(index)+" not a number", func() {
			bad := append([]any{}, good...)
			bad[index] = "nope"

			_, err := parseSlidingLogAddReply(bad)
			s.ErrorIs(err, ErrUnexpectedResponse)
			s.ErrorIs(err, strconv.ErrSyntax)
		})
	}

	s.Run("every bad field is reported", func() {
		_, err := parseSlidingLogAddReply([]any{"a", "b", 1, 2, "c"})
		for index := range 5 {
			s.ErrorContains(err, "field "+strconv.Itoa(index))
		}
	})

	s.Run("short reply", func() {
		_, err := parseSlidingLogAddReply(good[:4])
		s.ErrorIs(err, ErrUnexpectedResponse)
	})
}

func (s *SlidingLogSuite) TestStatsFromReply() {
	const sec = int64(time.Second)
	now := int64(1700000000000005000)
	reply := func(count, remaining, earliest, collisions int64) []any {
		return []any{count, remaining, strconv.FormatInt(earliest, 10), strconv.FormatInt(now, 10), collisions}
	}

	logger, hook := logrustest.NewNullLogger()
	logger.SetLevel(logrus.DebugLevel)
	rl := NewSlidingLogRedis(nil, nil, WithLogger(logger))

	for name, tc := range map[string]struct {
		reply []any
		want  Stats
	}{
		"slots left":      {reply(1, 1, now, 0), Stats{Count: 1, Remaining: 1, Limit: 3, Reset: 0}},
		"last slot":       {reply(2, 0, now, 0), Stats{Count: 2, Remaining: 0, Limit: 3, Reset: 10 * time.Second}},
		"blocked":         {reply(3, 0, now-6*sec, 0), Stats{Count: 3, Remaining: 0, Limit: 3, Reset: 4 * time.Second}},
		"stale earliest":  {reply(3, 0, now-11*sec, 0), Stats{Count: 3, Remaining: 0, Limit: 3, Reset: 0}},
		"with collisions": {reply(1, 1, now, 2), Stats{Count: 1, Remaining: 1, Limit: 3, Reset: 0}},
	} {
		s.Run(name, func() {
			hook.Reset()

			got, err := rl.statsFromReply(tc.reply, s.key, 3, 10)
			s.Require().NoError(err)
			s.Equal(tc.want, got)

			if tc.reply[4].(int64) > 0 {
				s.Require().Len(hook.Entries, 1)
				s.Equal(logrus.DebugLevel, hook.LastEntry().Level)
				s.Equal(s.key, hook.LastEntry().Data["key"])
			} else {
				s.Empty(hook.Entries)
			}
		})
	}

	s.Run("bad reply", func() {
		got, err := rl.statsFromReply(reply(1, 1, now, 0)[:4], s.key, 3, 10)
		s.ErrorIs(err, ErrUnexpectedResponse)
		s.Equal(NewEmptyStats(), got)
	})
}

func (s *SlidingLogSuite) TestNewSlidingLog() {
	conf, err := config.New()
	s.Require().NoError(err)

	rc := storage.NewConnectionHandler(s.ctx())
	go rc.Connect(s.ctx(), nil, conf)

	timeout, cancel := context.WithTimeout(s.ctx(), time.Second)
	defer cancel()
	s.Require().True(rc.WaitConnect(timeout), "redis not reachable")

	rl, err := NewSlidingLog(&storage.RedisCluster{KeyPrefix: "test-cluster", ConnectionHandler: rc}, allowAll)
	s.Require().NoError(err)

	_, blocked, err := rl.Do(s.ctx(), s.key, 3, 10)
	s.Require().NoError(err)
	s.False(blocked)
}

// TestUniqueMembers checks that every hit lands in the log, even when the redis
// clock has not moved on since the previous one.
func (s *SlidingLogSuite) TestUniqueMembers() {
	rl := NewSlidingLogRedis(s.db, allowAll)

	for range testRequestCount {
		_, _, err := rl.Do(s.ctx(), s.key, int64(testRequestCount), 10)
		s.Require().NoError(err)
	}

	count, err := s.db.ZCard(s.ctx(), s.key).Result()
	s.Require().NoError(err)
	s.Equal(int64(testRequestCount), count)

	// members stay plain nanosecond integers so older gateways can parse them
	members, err := s.db.ZRange(s.ctx(), s.key, 0, -1).Result()
	s.Require().NoError(err)
	for _, m := range members {
		_, err := strconv.ParseInt(m, 10, 64)
		s.NoError(err, m)
	}
}

func BenchmarkSlidingLog(b *testing.B) {
	ctx := b.Context()
	db := connectRedis(b)

	// happy path of the script: first ZADD NX succeeds
	b.Run("do", func(b *testing.B) {
		rl := NewSlidingLogRedis(db, allowAll)
		key := newKey(b, db)

		for i := 0; i < b.N; i++ {
			_, _, err := rl.Do(ctx, key, int64(b.N), 60)
			assert.NoError(b, err)
		}
	})

	// collision path: the member for this microsecond exists n times already
	for _, collisions := range []int{0, 1, 10, 100, 998} {
		b.Run("member collisions/"+strconv.Itoa(collisions), func(b *testing.B) {
			key := newKey(b, db)
			// like the script: microsecond time padded with "000"
			nowStr := strconv.FormatInt(time.Now().UnixMicro()*1000, 10)

			// like the script: every hit of a microsecond carries that microsecond's score
			score, err := strconv.ParseFloat(nowStr, 64)
			require.NoError(b, err)

			var members []redis.Z
			for seq := range collisions {
				members = append(members, redis.Z{Score: score, Member: nowStr[:len(nowStr)-3] + fmt.Sprintf("%03d", seq)})
			}

			for i := 0; i < b.N; i++ {
				b.StopTimer()
				require.NoError(b, db.Del(ctx, key).Err())
				if len(members) > 0 {
					require.NoError(b, db.ZAdd(ctx, key, members...).Err())
				}
				b.StartTimer()

				require.NoError(b, memberCollision.Run(ctx, db, []string{key}, nowStr).Err())
			}
		})
	}
}

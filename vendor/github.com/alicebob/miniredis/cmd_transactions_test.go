package miniredis

import (
	"testing"

	"github.com/garyburd/redigo/redis"
)

func TestMulti(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// Do accept MULTI, but use it as a no-op
	r, err := redis.String(c.Do("MULTI"))
	ok(t, err)
	equals(t, "OK", r)
}

func TestExec(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// Exec without MULTI.
	_, err = c.Do("EXEC")
	assert(t, err != nil, "do EXEC error")
}

func TestDiscard(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// DISCARD without MULTI.
	_, err = c.Do("DISCARD")
	assert(t, err != nil, "do DISCARD error")
}

func TestWatch(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// Simple WATCH
	r, err := redis.String(c.Do("WATCH", "foo"))
	ok(t, err)
	equals(t, "OK", r)

	// Can't do WATCH in a MULTI
	{
		_, err = redis.String(c.Do("MULTI"))
		ok(t, err)
		_, err = redis.String(c.Do("WATCH", "foo"))
		assert(t, err != nil, "do WATCH error")
	}
}

// Test simple multi/exec block.
func TestSimpleTransaction(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	b, err := redis.String(c.Do("MULTI"))
	ok(t, err)
	equals(t, "OK", b)

	b, err = redis.String(c.Do("SET", "aap", 1))
	ok(t, err)
	equals(t, "QUEUED", b)

	// Not set yet.
	equals(t, false, s.Exists("aap"))

	v, err := redis.Values(c.Do("EXEC"))
	ok(t, err)
	equals(t, 1, len(redis.Args(v)))
	equals(t, "OK", v[0])

	// SET should be back to normal mode
	b, err = redis.String(c.Do("SET", "aap", 1))
	ok(t, err)
	equals(t, "OK", b)
}

func TestDiscardTransaction(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.Set("aap", "noot")

	b, err := redis.String(c.Do("MULTI"))
	ok(t, err)
	equals(t, "OK", b)

	b, err = redis.String(c.Do("SET", "aap", "mies"))
	ok(t, err)
	equals(t, "QUEUED", b)

	// Not committed
	s.CheckGet(t, "aap", "noot")

	v, err := redis.String(c.Do("DISCARD"))
	ok(t, err)
	equals(t, "OK", v)

	// TX didn't get executed
	s.CheckGet(t, "aap", "noot")
}

func TestTxQueueErr(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	b, err := redis.String(c.Do("MULTI"))
	ok(t, err)
	equals(t, "OK", b)

	b, err = redis.String(c.Do("SET", "aap", "mies"))
	ok(t, err)
	equals(t, "QUEUED", b)

	// That's an error!
	_, err = redis.String(c.Do("SET", "aap"))
	assert(t, err != nil, "do SET error")

	// Thisone is ok again
	b, err = redis.String(c.Do("SET", "noot", "vuur"))
	ok(t, err)
	equals(t, "QUEUED", b)

	_, err = redis.String(c.Do("EXEC"))
	assert(t, err != nil, "do EXEC error")

	// Didn't get EXECed
	equals(t, false, s.Exists("aap"))
}

func TestTxWatch(t *testing.T) {
	// Watch with no error.
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.Set("one", "two")
	b, err := redis.String(c.Do("WATCH", "one"))
	ok(t, err)
	equals(t, "OK", b)

	b, err = redis.String(c.Do("MULTI"))
	ok(t, err)
	equals(t, "OK", b)

	b, err = redis.String(c.Do("GET", "one"))
	ok(t, err)
	equals(t, "QUEUED", b)

	v, err := redis.Values(c.Do("EXEC"))
	ok(t, err)
	equals(t, 1, len(v))
	equals(t, []byte("two"), v[0])
}

func TestTxWatchErr(t *testing.T) {
	// Watch with en error.
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)
	c2, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.Set("one", "two")
	b, err := redis.String(c.Do("WATCH", "one"))
	ok(t, err)
	equals(t, "OK", b)

	// Here comes client 2
	b, err = redis.String(c2.Do("SET", "one", "three"))
	ok(t, err)
	equals(t, "OK", b)

	b, err = redis.String(c.Do("MULTI"))
	ok(t, err)
	equals(t, "OK", b)

	b, err = redis.String(c.Do("GET", "one"))
	ok(t, err)
	equals(t, "QUEUED", b)

	v, err := redis.Values(c.Do("EXEC"))
	ok(t, err)
	equals(t, 0, len(v))

	// It did get updated, and we're not in a transaction anymore.
	b, err = redis.String(c.Do("GET", "one"))
	ok(t, err)
	equals(t, "three", b)
}

func TestUnwatch(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)
	c2, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.Set("one", "two")
	b, err := redis.String(c.Do("WATCH", "one"))
	ok(t, err)
	equals(t, "OK", b)

	b, err = redis.String(c.Do("UNWATCH"))
	ok(t, err)
	equals(t, "OK", b)

	// Here comes client 2
	b, err = redis.String(c2.Do("SET", "one", "three"))
	ok(t, err)
	equals(t, "OK", b)

	b, err = redis.String(c.Do("MULTI"))
	ok(t, err)
	equals(t, "OK", b)

	b, err = redis.String(c.Do("SET", "one", "four"))
	ok(t, err)
	equals(t, "QUEUED", b)

	v, err := redis.Values(c.Do("EXEC"))
	ok(t, err)
	equals(t, 1, len(v))
	equals(t, "OK", v[0])

	// It did get updated by our TX
	b, err = redis.String(c.Do("GET", "one"))
	ok(t, err)
	equals(t, "four", b)
}

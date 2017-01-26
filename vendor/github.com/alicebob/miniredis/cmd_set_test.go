package miniredis

import (
	"sort"
	"testing"

	"github.com/garyburd/redigo/redis"
)

// Test SADD / SMEMBERS.
func TestSadd(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	{
		b, err := redis.Int(c.Do("SADD", "s", "aap", "noot", "mies"))
		ok(t, err)
		equals(t, 3, b) // New elements.

		members, err := s.Members("s")
		ok(t, err)
		equals(t, []string{"aap", "mies", "noot"}, members)

		m, err := redis.Strings(c.Do("SMEMBERS", "s"))
		ok(t, err)
		equals(t, []string{"aap", "mies", "noot"}, m)
	}

	{
		b, err := redis.String(c.Do("TYPE", "s"))
		ok(t, err)
		equals(t, "set", b)
	}

	// SMEMBERS on an nonexisting key
	{
		m, err := redis.Strings(c.Do("SMEMBERS", "nosuch"))
		ok(t, err)
		equals(t, []string{}, m)
	}

	{
		b, err := redis.Int(c.Do("SADD", "s", "new", "noot", "mies"))
		ok(t, err)
		equals(t, 1, b) // Only one new field.

		members, err := s.Members("s")
		ok(t, err)
		equals(t, []string{"aap", "mies", "new", "noot"}, members)
	}

	// Direct usage
	{
		added, err := s.SetAdd("s1", "aap")
		ok(t, err)
		equals(t, 1, added)

		members, err := s.Members("s1")
		ok(t, err)
		equals(t, []string{"aap"}, members)
	}

	// Wrong type of key
	{
		_, err := redis.String(c.Do("SET", "str", "value"))
		ok(t, err)
		_, err = redis.Int(c.Do("SADD", "str", "hi"))
		assert(t, err != nil, "SADD error")
		_, err = redis.Int(c.Do("SMEMBERS", "str"))
		assert(t, err != nil, "MEMBERS error")
		// Wrong argument counts
		_, err = redis.String(c.Do("SADD"))
		assert(t, err != nil, "SADD error")
		_, err = redis.String(c.Do("SADD", "set"))
		assert(t, err != nil, "SADD error")
		_, err = redis.String(c.Do("SMEMBERS"))
		assert(t, err != nil, "SMEMBERS error")
		_, err = redis.String(c.Do("SMEMBERS", "set", "spurious"))
		assert(t, err != nil, "SMEMBERS error")
	}

}

// Test SISMEMBER
func TestSismember(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.SetAdd("s", "aap", "noot", "mies")

	{
		b, err := redis.Int(c.Do("SISMEMBER", "s", "aap"))
		ok(t, err)
		equals(t, 1, b)

		b, err = redis.Int(c.Do("SISMEMBER", "s", "nosuch"))
		ok(t, err)
		equals(t, 0, b)
	}

	// a nonexisting key
	{
		b, err := redis.Int(c.Do("SISMEMBER", "nosuch", "nosuch"))
		ok(t, err)
		equals(t, 0, b)
	}

	// Direct usage
	{
		isMember, err := s.IsMember("s", "noot")
		ok(t, err)
		equals(t, true, isMember)
	}

	// Wrong type of key
	{
		_, err := redis.String(c.Do("SET", "str", "value"))
		ok(t, err)
		_, err = redis.Int(c.Do("SISMEMBER", "str"))
		assert(t, err != nil, "SISMEMBER error")
		// Wrong argument counts
		_, err = redis.String(c.Do("SISMEMBER"))
		assert(t, err != nil, "SISMEMBER error")
		_, err = redis.String(c.Do("SISMEMBER", "set"))
		assert(t, err != nil, "SISMEMBER error")
		_, err = redis.String(c.Do("SISMEMBER", "set", "spurious", "args"))
		assert(t, err != nil, "SISMEMBER error")
	}

}

// Test SREM
func TestSrem(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.SetAdd("s", "aap", "noot", "mies", "vuur")

	{
		b, err := redis.Int(c.Do("SREM", "s", "aap", "noot"))
		ok(t, err)
		equals(t, 2, b)

		members, err := s.Members("s")
		ok(t, err)
		equals(t, []string{"mies", "vuur"}, members)
	}

	// a nonexisting field
	{
		b, err := redis.Int(c.Do("SREM", "s", "nosuch"))
		ok(t, err)
		equals(t, 0, b)
	}

	// a nonexisting key
	{
		b, err := redis.Int(c.Do("SREM", "nosuch", "nosuch"))
		ok(t, err)
		equals(t, 0, b)
	}

	// Direct usage
	{
		b, err := s.SRem("s", "mies")
		ok(t, err)
		equals(t, 1, b)

		members, err := s.Members("s")
		ok(t, err)
		equals(t, []string{"vuur"}, members)
	}

	// Wrong type of key
	{
		_, err := redis.String(c.Do("SET", "str", "value"))
		ok(t, err)
		_, err = redis.Int(c.Do("SREM", "str", "value"))
		assert(t, err != nil, "SREM error")
		// Wrong argument counts
		_, err = redis.String(c.Do("SREM"))
		assert(t, err != nil, "SREM error")
		_, err = redis.String(c.Do("SREM", "set"))
		assert(t, err != nil, "SREM error")
		_, err = redis.String(c.Do("SREM", "set", "spurious", "args"))
		assert(t, err != nil, "SREM error")
	}
}

// Test SMOVE
func TestSmove(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.SetAdd("s", "aap", "noot")

	{
		b, err := redis.Int(c.Do("SMOVE", "s", "s2", "aap"))
		ok(t, err)
		equals(t, 1, b)

		m, err := s.IsMember("s", "aap")
		ok(t, err)
		equals(t, false, m)
		m, err = s.IsMember("s2", "aap")
		ok(t, err)
		equals(t, true, m)
	}

	// Move away the last member
	{
		b, err := redis.Int(c.Do("SMOVE", "s", "s2", "noot"))
		ok(t, err)
		equals(t, 1, b)

		equals(t, false, s.Exists("s"))

		m, err := s.IsMember("s2", "noot")
		ok(t, err)
		equals(t, true, m)
	}

	// a nonexisting member
	{
		b, err := redis.Int(c.Do("SMOVE", "s", "s2", "nosuch"))
		ok(t, err)
		equals(t, 0, b)
	}

	// a nonexisting key
	{
		b, err := redis.Int(c.Do("SMOVE", "nosuch", "nosuch2", "nosuch"))
		ok(t, err)
		equals(t, 0, b)
	}

	// Wrong type of key
	{
		_, err := redis.String(c.Do("SET", "str", "value"))
		ok(t, err)
		_, err = redis.Int(c.Do("SMOVE", "str", "dst", "value"))
		assert(t, err != nil, "SMOVE error")
		_, err = redis.Int(c.Do("SMOVE", "s2", "str", "value"))
		assert(t, err != nil, "SMOVE error")
		// Wrong argument counts
		_, err = redis.String(c.Do("SMOVE"))
		assert(t, err != nil, "SMOVE error")
		_, err = redis.String(c.Do("SMOVE", "set"))
		assert(t, err != nil, "SMOVE error")
		_, err = redis.String(c.Do("SMOVE", "set", "set2"))
		assert(t, err != nil, "SMOVE error")
		_, err = redis.String(c.Do("SMOVE", "set", "set2", "spurious", "args"))
		assert(t, err != nil, "SMOVE error")
	}
}

// Test SPOP
func TestSpop(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.SetAdd("s", "aap", "noot")

	{
		el, err := redis.String(c.Do("SPOP", "s"))
		ok(t, err)
		assert(t, el == "aap" || el == "noot", "spop got something")

		el, err = redis.String(c.Do("SPOP", "s"))
		ok(t, err)
		assert(t, el == "aap" || el == "noot", "spop got something")

		assert(t, !s.Exists("s"), "all spopped away")
	}

	// a nonexisting key
	{
		b, err := c.Do("SPOP", "nosuch")
		ok(t, err)
		equals(t, nil, b)
	}

	// various errors
	{
		s.SetAdd("chk", "aap", "noot")
		s.Set("str", "value")

		_, err = redis.String(c.Do("SMOVE"))
		assert(t, err != nil, "SMOVE error")
		_, err = redis.String(c.Do("SMOVE", "chk", "set2"))
		assert(t, err != nil, "SMOVE error")

		_, err = c.Do("SPOP", "str")
		assert(t, err != nil, "SPOP error")
	}

	// count argument
	{
		s.SetAdd("s", "aap", "noot", "mies", "vuur")
		el, err := redis.Strings(c.Do("SPOP", "s", 2))
		ok(t, err)
		assert(t, len(el) == 2, "SPOP s 2")
		members, err := s.Members("s")
		ok(t, err)
		assert(t, len(members) == 2, "SPOP s 2")
	}
}

// Test SRANDMEMBER
func TestSrandmember(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.SetAdd("s", "aap", "noot", "mies")

	// No count
	{
		el, err := redis.String(c.Do("SRANDMEMBER", "s"))
		ok(t, err)
		assert(t, el == "aap" || el == "noot" || el == "mies", "srandmember got something")
	}

	// Positive count
	{
		els, err := redis.Strings(c.Do("SRANDMEMBER", "s", 2))
		ok(t, err)
		equals(t, 2, len(els))
	}

	// Negative count
	{
		els, err := redis.Strings(c.Do("SRANDMEMBER", "s", -2))
		ok(t, err)
		equals(t, 2, len(els))
	}

	// a nonexisting key
	{
		b, err := c.Do("SRANDMEMBER", "nosuch")
		ok(t, err)
		equals(t, nil, b)
	}

	// Various errors
	{
		s.SetAdd("chk", "aap", "noot")
		s.Set("str", "value")

		_, err = redis.String(c.Do("SRANDMEMBER"))
		assert(t, err != nil, "SRANDMEMBER error")
		_, err = redis.String(c.Do("SRANDMEMBER", "chk", "noint"))
		assert(t, err != nil, "SRANDMEMBER error")
		_, err = redis.String(c.Do("SRANDMEMBER", "chk", 1, "toomanu"))
		assert(t, err != nil, "SRANDMEMBER error")

		_, err = c.Do("SRANDMEMBER", "str")
		assert(t, err != nil, "SRANDMEMBER error")
	}
}

// Test SDIFF
func TestSdiff(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.SetAdd("s1", "aap", "noot", "mies")
	s.SetAdd("s2", "noot", "mies", "vuur")
	s.SetAdd("s3", "aap", "mies", "wim")

	// Simple case
	{
		els, err := redis.Strings(c.Do("SDIFF", "s1", "s2"))
		ok(t, err)
		equals(t, []string{"aap"}, els)
	}

	// No other set
	{
		els, err := redis.Strings(c.Do("SDIFF", "s1"))
		ok(t, err)
		sort.Strings(els)
		equals(t, []string{"aap", "mies", "noot"}, els)
	}

	// 3 sets
	{
		els, err := redis.Strings(c.Do("SDIFF", "s1", "s2", "s3"))
		ok(t, err)
		equals(t, []string{}, els)
	}

	// A nonexisting key
	{
		els, err := redis.Strings(c.Do("SDIFF", "s9"))
		ok(t, err)
		equals(t, []string{}, els)
	}

	// Various errors
	{
		s.SetAdd("chk", "aap", "noot")
		s.Set("str", "value")

		_, err = redis.String(c.Do("SDIFF"))
		assert(t, err != nil, "SDIFF error")
		_, err = redis.String(c.Do("SDIFF", "str"))
		assert(t, err != nil, "SDIFF error")
		_, err = redis.String(c.Do("SDIFF", "chk", "str"))
		assert(t, err != nil, "SDIFF error")
	}
}

// Test SDIFFSTORE
func TestSdiffstore(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.SetAdd("s1", "aap", "noot", "mies")
	s.SetAdd("s2", "noot", "mies", "vuur")
	s.SetAdd("s3", "aap", "mies", "wim")

	// Simple case
	{
		i, err := redis.Int(c.Do("SDIFFSTORE", "res", "s1", "s3"))
		ok(t, err)
		equals(t, 1, i)
		s.CheckSet(t, "res", "noot")
	}

	// Various errors
	{
		s.SetAdd("chk", "aap", "noot")
		s.Set("str", "value")

		_, err = redis.String(c.Do("SDIFFSTORE"))
		assert(t, err != nil, "SDIFFSTORE error")
		_, err = redis.String(c.Do("SDIFFSTORE", "t"))
		assert(t, err != nil, "SDIFFSTORE error")
		_, err = redis.String(c.Do("SDIFFSTORE", "t", "str"))
		assert(t, err != nil, "SDIFFSTORE error")
	}
}

// Test SINTER
func TestSinter(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.SetAdd("s1", "aap", "noot", "mies")
	s.SetAdd("s2", "noot", "mies", "vuur")
	s.SetAdd("s3", "aap", "mies", "wim")

	// Simple case
	{
		els, err := redis.Strings(c.Do("SINTER", "s1", "s2"))
		ok(t, err)
		sort.Strings(els)
		equals(t, []string{"mies", "noot"}, els)
	}

	// No other set
	{
		els, err := redis.Strings(c.Do("SINTER", "s1"))
		ok(t, err)
		sort.Strings(els)
		equals(t, []string{"aap", "mies", "noot"}, els)
	}

	// 3 sets
	{
		els, err := redis.Strings(c.Do("SINTER", "s1", "s2", "s3"))
		ok(t, err)
		equals(t, []string{"mies"}, els)
	}

	// A nonexisting key
	{
		els, err := redis.Strings(c.Do("SINTER", "s9"))
		ok(t, err)
		equals(t, []string{}, els)
	}

	// Various errors
	{
		s.SetAdd("chk", "aap", "noot")
		s.Set("str", "value")

		_, err = redis.String(c.Do("SINTER"))
		assert(t, err != nil, "SINTER error")
		_, err = redis.String(c.Do("SINTER", "str"))
		assert(t, err != nil, "SINTER error")
		_, err = redis.String(c.Do("SINTER", "chk", "str"))
		assert(t, err != nil, "SINTER error")
	}
}

// Test SINTERSTORE
func TestSinterstore(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.SetAdd("s1", "aap", "noot", "mies")
	s.SetAdd("s2", "noot", "mies", "vuur")
	s.SetAdd("s3", "aap", "mies", "wim")

	// Simple case
	{
		i, err := redis.Int(c.Do("SINTERSTORE", "res", "s1", "s3"))
		ok(t, err)
		equals(t, 2, i)
		s.CheckSet(t, "res", "aap", "mies")
	}

	// Various errors
	{
		s.SetAdd("chk", "aap", "noot")
		s.Set("str", "value")

		_, err = redis.String(c.Do("SINTERSTORE"))
		assert(t, err != nil, "SINTERSTORE error")
		_, err = redis.String(c.Do("SINTERSTORE", "t"))
		assert(t, err != nil, "SINTERSTORE error")
		_, err = redis.String(c.Do("SINTERSTORE", "t", "str"))
		assert(t, err != nil, "SINTERSTORE error")
	}
}

// Test SUNION
func TestSunion(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.SetAdd("s1", "aap", "noot", "mies")
	s.SetAdd("s2", "noot", "mies", "vuur")
	s.SetAdd("s3", "aap", "mies", "wim")

	// Simple case
	{
		els, err := redis.Strings(c.Do("SUNION", "s1", "s2"))
		ok(t, err)
		sort.Strings(els)
		equals(t, []string{"aap", "mies", "noot", "vuur"}, els)
	}

	// No other set
	{
		els, err := redis.Strings(c.Do("SUNION", "s1"))
		ok(t, err)
		sort.Strings(els)
		equals(t, []string{"aap", "mies", "noot"}, els)
	}

	// 3 sets
	{
		els, err := redis.Strings(c.Do("SUNION", "s1", "s2", "s3"))
		ok(t, err)
		sort.Strings(els)
		equals(t, []string{"aap", "mies", "noot", "vuur", "wim"}, els)
	}

	// A nonexisting key
	{
		els, err := redis.Strings(c.Do("SUNION", "s9"))
		ok(t, err)
		equals(t, []string{}, els)
	}

	// Various errors
	{
		s.SetAdd("chk", "aap", "noot")
		s.Set("str", "value")

		_, err = redis.String(c.Do("SUNION"))
		assert(t, err != nil, "SUNION error")
		_, err = redis.String(c.Do("SUNION", "str"))
		assert(t, err != nil, "SUNION error")
		_, err = redis.String(c.Do("SUNION", "chk", "str"))
		assert(t, err != nil, "SUNION error")
	}
}

// Test SUNIONSTORE
func TestSunionstore(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.SetAdd("s1", "aap", "noot", "mies")
	s.SetAdd("s2", "noot", "mies", "vuur")
	s.SetAdd("s3", "aap", "mies", "wim")

	// Simple case
	{
		i, err := redis.Int(c.Do("SUNIONSTORE", "res", "s1", "s3"))
		ok(t, err)
		equals(t, 4, i)
		s.CheckSet(t, "res", "aap", "mies", "noot", "wim")
	}

	// Various errors
	{
		s.SetAdd("chk", "aap", "noot")
		s.Set("str", "value")

		_, err = redis.String(c.Do("SUNIONSTORE"))
		assert(t, err != nil, "SUNIONSTORE error")
		_, err = redis.String(c.Do("SUNIONSTORE", "t"))
		assert(t, err != nil, "SUNIONSTORE error")
		_, err = redis.String(c.Do("SUNIONSTORE", "t", "str"))
		assert(t, err != nil, "SUNIONSTORE error")
	}
}

func TestSscan(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// We cheat with sscan. It always returns everything.

	s.SetAdd("set", "value1", "value2")

	// No problem
	{
		res, err := redis.Values(c.Do("SSCAN", "set", 0))
		ok(t, err)
		equals(t, 2, len(res))

		var c int
		var keys []string
		_, err = redis.Scan(res, &c, &keys)
		ok(t, err)
		equals(t, 0, c)
		equals(t, []string{"value1", "value2"}, keys)
	}

	// Invalid cursor
	{
		res, err := redis.Values(c.Do("SSCAN", "set", 42))
		ok(t, err)
		equals(t, 2, len(res))

		var c int
		var keys []string
		_, err = redis.Scan(res, &c, &keys)
		ok(t, err)
		equals(t, 0, c)
		equals(t, []string(nil), keys)
	}

	// COUNT (ignored)
	{
		res, err := redis.Values(c.Do("SSCAN", "set", 0, "COUNT", 200))
		ok(t, err)
		equals(t, 2, len(res))

		var c int
		var keys []string
		_, err = redis.Scan(res, &c, &keys)
		ok(t, err)
		equals(t, 0, c)
		equals(t, []string{"value1", "value2"}, keys)
	}

	// MATCH
	{
		s.SetAdd("set", "aap", "noot", "mies")
		res, err := redis.Values(c.Do("SSCAN", "set", 0, "MATCH", "mi*"))
		ok(t, err)
		equals(t, 2, len(res))

		var c int
		var keys []string
		_, err = redis.Scan(res, &c, &keys)
		ok(t, err)
		equals(t, 0, c)
		equals(t, []string{"mies"}, keys)
	}

	// Wrong usage
	{
		_, err := redis.Int(c.Do("SSCAN"))
		assert(t, err != nil, "do SSCAN error")
		_, err = redis.Int(c.Do("SSCAN", "set"))
		assert(t, err != nil, "do SSCAN error")
		_, err = redis.Int(c.Do("SSCAN", "set", "noint"))
		assert(t, err != nil, "do SSCAN error")
		_, err = redis.Int(c.Do("SSCAN", "set", 1, "MATCH"))
		assert(t, err != nil, "do SSCAN error")
		_, err = redis.Int(c.Do("SSCAN", "set", 1, "COUNT"))
		assert(t, err != nil, "do SSCAN error")
		_, err = redis.Int(c.Do("SSCAN", "set", 1, "COUNT", "noint"))
		assert(t, err != nil, "do SSCAN error")
		s.Set("str", "value")
		_, err = redis.Int(c.Do("SSCAN", "str", 1))
		assert(t, err != nil, "do SSCAN error")
	}
}

package miniredis

import (
	"testing"

	"github.com/garyburd/redigo/redis"
)

// Test simple GET/SET keys
func TestString(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// SET command
	{
		v, err := redis.String(c.Do("SET", "foo", "bar"))
		ok(t, err)
		equals(t, "OK", v)
	}

	// GET command
	{
		v, err := redis.String(c.Do("GET", "foo"))
		ok(t, err)
		equals(t, "bar", v)
	}

	// Query server directly.
	{
		got, err := s.Get("foo")
		ok(t, err)
		equals(t, "bar", got)
	}

	// Use Set directly
	{
		ok(t, s.Set("aap", "noot"))
		s.CheckGet(t, "aap", "noot")
		v, err := redis.String(c.Do("GET", "aap"))
		ok(t, err)
		equals(t, "noot", v)
		s.CheckGet(t, "aap", "noot")
		// Re-set.
		ok(t, s.Set("aap", "noot2"))
	}

	// GET a non-existing key. Should be nil.
	{
		b, err := c.Do("GET", "reallynosuchkey")
		ok(t, err)
		equals(t, nil, b)
	}

	// Wrong usage.
	{
		_, err := c.Do("HSET", "wim", "zus", "jet")
		ok(t, err)
		_, err = c.Do("GET", "wim")
		assert(t, err != nil, "no GET error")
	}
}

func TestSet(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// Simple case
	{
		v, err := redis.String(c.Do("SET", "aap", "noot"))
		ok(t, err)
		equals(t, "OK", v)
	}

	// Overwrite other types.
	{
		s.HSet("wim", "teun", "vuur")
		v, err := redis.String(c.Do("SET", "wim", "gijs"))
		ok(t, err)
		equals(t, "OK", v)
		s.CheckGet(t, "wim", "gijs")
	}

	// NX argument
	{
		// new key
		v, err := redis.String(c.Do("SET", "mies", "toon", "NX"))
		ok(t, err)
		equals(t, "OK", v)
		// now existing key
		nx, err := c.Do("SET", "mies", "toon", "NX")
		ok(t, err)
		equals(t, nil, nx)
		// lowercase NX is no problem
		nx, err = c.Do("SET", "mies", "toon", "nx")
		ok(t, err)
		equals(t, nil, nx)
	}

	// XX argument - only set if exists
	{
		// new key, no go
		v, err := c.Do("SET", "one", "two", "XX")
		ok(t, err)
		equals(t, nil, v)

		s.Set("one", "three")

		v, err = c.Do("SET", "one", "two", "XX")
		ok(t, err)
		equals(t, "OK", v)
		s.CheckGet(t, "one", "two")

		// XX with another key type
		s.HSet("eleven", "twelve", "thirteen")
		h, err := redis.String(c.Do("SET", "eleven", "fourteen", "XX"))
		ok(t, err)
		equals(t, "OK", h)
		s.CheckGet(t, "eleven", "fourteen")
	}

	// EX or PX argument. Expire values.
	{
		v, err := c.Do("SET", "one", "two", "EX", 1299)
		ok(t, err)
		equals(t, "OK", v)
		s.CheckGet(t, "one", "two")
		equals(t, 1299, s.Expire("one"))

		v, err = c.Do("SET", "three", "four", "PX", 8888)
		ok(t, err)
		equals(t, "OK", v)
		s.CheckGet(t, "three", "four")
		equals(t, 8888, s.Expire("three"))

		_, err = c.Do("SET", "one", "two", "EX", "notimestamp")
		assert(t, err != nil, "no SET error on invalid EX")

		_, err = c.Do("SET", "one", "two", "EX")
		assert(t, err != nil, "no SET error on missing EX argument")
	}

	// Invalid argument
	{
		_, err := c.Do("SET", "one", "two", "FOO")
		assert(t, err != nil, "no SET error")
	}
}

func TestMget(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.Set("zus", "jet")
	s.Set("teun", "vuur")
	s.Set("gijs", "lam")
	s.Set("kees", "bok")
	{
		v, err := redis.Values(c.Do("MGET", "zus", "nosuch", "kees"))
		ok(t, err)
		equals(t, 3, len(v))
		equals(t, "jet", string(v[0].([]byte)))
		equals(t, nil, v[1])
		equals(t, "bok", string(v[2].([]byte)))
	}

	// Wrong key type returns nil
	{
		s.HSet("aap", "foo", "bar")
		v, err := redis.Values(c.Do("MGET", "aap"))
		ok(t, err)
		equals(t, 1, len(v))
		equals(t, nil, v[0])
	}
}

func TestMset(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	{
		v, err := redis.String(c.Do("MSET", "zus", "jet", "teun", "vuur", "gijs", "lam"))
		ok(t, err)
		equals(t, "OK", v)
		s.CheckGet(t, "zus", "jet")
		s.CheckGet(t, "teun", "vuur")
		s.CheckGet(t, "gijs", "lam")
	}

	// Other types are overwritten
	{
		s.HSet("aap", "foo", "bar")
		v, err := redis.String(c.Do("MSET", "aap", "jet"))
		ok(t, err)
		equals(t, "OK", v)
		s.CheckGet(t, "aap", "jet")
	}

	// Odd argument list is not OK
	{
		_, err := redis.String(c.Do("MSET", "zus", "jet", "teun"))
		assert(t, err != nil, "No MSET error")
	}

	// TTL is cleared
	{
		s.Set("foo", "bar")
		s.HSet("aap", "foo", "bar") // even for weird keys.
		s.SetExpire("aap", 999)
		s.SetExpire("foo", 999)
		v, err := redis.String(c.Do("MSET", "aap", "noot", "foo", "baz"))
		ok(t, err)
		equals(t, "OK", v)
		equals(t, 0, s.Expire("aap"))
		equals(t, 0, s.Expire("foo"))
	}
}

func TestSetex(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// Usual case
	{
		v, err := redis.String(c.Do("SETEX", "aap", 1234, "noot"))
		ok(t, err)
		equals(t, "OK", v)
		s.CheckGet(t, "aap", "noot")
		equals(t, 1234, s.Expire("aap"))
	}

	// Same thing
	{
		_, err := redis.String(c.Do("SETEX", "aap", "1234", "noot"))
		ok(t, err)
	}

	// Error cases
	{
		_, err := redis.String(c.Do("SETEX", "aap", "nottl", "noot"))
		assert(t, err != nil, "no SETEX error")
		_, err = redis.String(c.Do("SETEX", "aap"))
		assert(t, err != nil, "no SETEX error")
		_, err = redis.String(c.Do("SETEX", "aap", 12))
		assert(t, err != nil, "no SETEX error")
		_, err = redis.String(c.Do("SETEX", "aap", 12, "noot", "toomuch"))
		assert(t, err != nil, "no SETEX error")
	}
}

func TestPsetex(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// Usual case
	{
		v, err := redis.String(c.Do("PSETEX", "aap", 1234, "noot"))
		ok(t, err)
		equals(t, "OK", v)
		s.CheckGet(t, "aap", "noot")
		equals(t, 1234, s.Expire("aap")) // We set Milliseconds in Expire.
	}

	// Same thing
	{
		_, err := redis.String(c.Do("PSETEX", "aap", "1234", "noot"))
		ok(t, err)
	}

	// Error cases
	{
		_, err := redis.String(c.Do("PSETEX", "aap", "nottl", "noot"))
		assert(t, err != nil, "no PSETEX error")
		_, err = redis.String(c.Do("PSETEX", "aap"))
		assert(t, err != nil, "no PSETEX error")
		_, err = redis.String(c.Do("PSETEX", "aap", 12))
		assert(t, err != nil, "no PSETEX error")
		_, err = redis.String(c.Do("PSETEX", "aap", 12, "noot", "toomuch"))
		assert(t, err != nil, "no PSETEX error")
	}
}

func TestSetnx(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// Existing key
	{
		s.Set("foo", "bar")
		v, err := redis.Int(c.Do("SETNX", "foo", "not bar"))
		ok(t, err)
		equals(t, 0, v)
		s.CheckGet(t, "foo", "bar")
	}

	// New key
	{
		v, err := redis.Int(c.Do("SETNX", "notfoo", "also not bar"))
		ok(t, err)
		equals(t, 1, v)
		s.CheckGet(t, "notfoo", "also not bar")
	}

	// Existing key of a different type
	{
		s.HSet("foo", "bar", "baz")
		v, err := redis.Int(c.Do("SETNX", "foo", "not bar"))
		ok(t, err)
		equals(t, 0, v)
		equals(t, "hash", s.Type("foo"))
		_, err = s.Get("foo")
		equals(t, ErrWrongType, err)
		equals(t, "baz", s.HGet("foo", "bar"))
	}
}

func TestIncr(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// Existing key
	{
		s.Set("foo", "12")
		v, err := redis.Int(c.Do("INCR", "foo"))
		ok(t, err)
		equals(t, 13, v)
		s.CheckGet(t, "foo", "13")
	}

	// Existing key, not an integer
	{
		s.Set("foo", "noint")
		_, err := redis.Int(c.Do("INCR", "foo"))
		assert(t, err != nil, "do INCR error")
	}

	// New key
	{
		v, err := redis.Int(c.Do("INCR", "bar"))
		ok(t, err)
		equals(t, 1, v)
		s.CheckGet(t, "bar", "1")
	}

	// Wrong type of existing key
	{
		s.HSet("wrong", "aap", "noot")
		_, err := redis.Int(c.Do("INCR", "wrong"))
		assert(t, err != nil, "do INCR error")
	}

	// Direct usage
	{
		i, err := s.Incr("count", 1)
		ok(t, err)
		equals(t, 1, i)
		i, err = s.Incr("count", 1)
		ok(t, err)
		equals(t, 2, i)
		_, err = s.Incr("wrong", 1)
		assert(t, err != nil, "do s.Incr error")
	}

	// Wrong usage
	{
		_, err := redis.Int(c.Do("INCR"))
		assert(t, err != nil, "do INCR error")
		_, err = redis.Int(c.Do("INCR", "new", "key"))
		assert(t, err != nil, "do INCR error")
	}
}

func TestIncrBy(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// Existing key
	{
		s.Set("foo", "12")
		v, err := redis.Int(c.Do("INCRBY", "foo", "400"))
		ok(t, err)
		equals(t, 412, v)
		s.CheckGet(t, "foo", "412")
	}

	// Existing key, not an integer
	{
		s.Set("foo", "noint")
		_, err := redis.Int(c.Do("INCRBY", "foo", "400"))
		assert(t, err != nil, "do INCRBY error")
	}

	// New key
	{
		v, err := redis.Int(c.Do("INCRBY", "bar", "4000"))
		ok(t, err)
		equals(t, 4000, v)
		s.CheckGet(t, "bar", "4000")
	}

	// Wrong type of existing key
	{
		s.HSet("wrong", "aap", "noot")
		_, err := redis.Int(c.Do("INCRBY", "wrong", "400"))
		assert(t, err != nil, "do INCRBY error")
	}

	// Amount not an interger
	{
		_, err := redis.Int(c.Do("INCRBY", "key", "noint"))
		assert(t, err != nil, "do INCRBY error")
	}

	// Wrong usage
	{
		_, err := redis.Int(c.Do("INCRBY"))
		assert(t, err != nil, "do INCRBY error")
		_, err = redis.Int(c.Do("INCRBY", "another", "new", "key"))
		assert(t, err != nil, "do INCRBY error")
	}
}

func TestIncrbyfloat(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// Existing key
	{
		s.Set("foo", "12")
		v, err := redis.Float64(c.Do("INCRBYFLOAT", "foo", "400.12"))
		ok(t, err)
		equals(t, 412.12, v)
		s.CheckGet(t, "foo", "412.12")
	}

	// Existing key, not a number
	{
		s.Set("foo", "noint")
		_, err := redis.Float64(c.Do("INCRBYFLOAT", "foo", "400"))
		assert(t, err != nil, "do INCRBYFLOAT error")
	}

	// New key
	{
		v, err := redis.Float64(c.Do("INCRBYFLOAT", "bar", "40.33"))
		ok(t, err)
		equals(t, 40.33, v)
		s.CheckGet(t, "bar", "40.33")
	}

	// Direct usage
	{
		s.Set("foo", "500.1")
		f, err := s.Incrfloat("foo", 12)
		ok(t, err)
		equals(t, 512.1, f)
		s.CheckGet(t, "foo", "512.1")

		s.HSet("wrong", "aap", "noot")
		_, err = s.Incrfloat("wrong", 12)
		assert(t, err != nil, "do s.Incrfloat() error")
	}

	// Wrong type of existing key
	{
		s.HSet("wrong", "aap", "noot")
		_, err := redis.Int(c.Do("INCRBYFLOAT", "wrong", "400"))
		assert(t, err != nil, "do INCRBYFLOAT error")
	}

	// Amount not a number
	{
		_, err := redis.Int(c.Do("INCRBYFLOAT", "key", "noint"))
		assert(t, err != nil, "do INCRBYFLOAT error")
	}

	// Wrong usage
	{
		_, err := redis.Int(c.Do("INCRBYFLOAT"))
		assert(t, err != nil, "do INCRBYFLOAT error")
		_, err = redis.Int(c.Do("INCRBYFLOAT", "another", "new", "key"))
		assert(t, err != nil, "do INCRBYFLOAT error")
	}
}

func TestDecrBy(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// Existing key
	{
		s.Set("foo", "12")
		v, err := redis.Int(c.Do("DECRBY", "foo", "400"))
		ok(t, err)
		equals(t, -388, v)
		s.CheckGet(t, "foo", "-388")
	}

	// Existing key, not an integer
	{
		s.Set("foo", "noint")
		_, err := redis.Int(c.Do("DECRBY", "foo", "400"))
		assert(t, err != nil, "do DECRBY error")
	}

	// New key
	{
		v, err := redis.Int(c.Do("DECRBY", "bar", "4000"))
		ok(t, err)
		equals(t, -4000, v)
		s.CheckGet(t, "bar", "-4000")
	}

	// Wrong type of existing key
	{
		s.HSet("wrong", "aap", "noot")
		_, err := redis.Int(c.Do("DECRBY", "wrong", "400"))
		assert(t, err != nil, "do DECRBY error")
	}

	// Amount not an interger
	{
		_, err := redis.Int(c.Do("DECRBY", "key", "noint"))
		assert(t, err != nil, "do DECRBY error")
	}

	// Wrong usage
	{
		_, err := redis.Int(c.Do("DECRBY"))
		assert(t, err != nil, "do DECRBY error")
		_, err = redis.Int(c.Do("DECRBY", "another", "new", "key"))
		assert(t, err != nil, "do DECRBY error")
	}
}

func TestDecr(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// Existing key
	{
		s.Set("foo", "12")
		v, err := redis.Int(c.Do("DECR", "foo"))
		ok(t, err)
		equals(t, 11, v)
		s.CheckGet(t, "foo", "11")
	}

	// Existing key, not an integer
	{
		s.Set("foo", "noint")
		_, err := redis.Int(c.Do("DECR", "foo"))
		assert(t, err != nil, "do DECR error")
	}

	// New key
	{
		v, err := redis.Int(c.Do("DECR", "bar"))
		ok(t, err)
		equals(t, -1, v)
		s.CheckGet(t, "bar", "-1")
	}

	// Wrong type of existing key
	{
		s.HSet("wrong", "aap", "noot")
		_, err := redis.Int(c.Do("DECR", "wrong"))
		assert(t, err != nil, "do DECR error")
	}

	// Wrong usage
	{
		_, err := redis.Int(c.Do("DECR"))
		assert(t, err != nil, "do DECR error")
		_, err = redis.Int(c.Do("DECR", "new", "key"))
		assert(t, err != nil, "do DECR error")
	}

	// Direct one works
	{
		s.Set("aap", "400")
		s.Incr("aap", +42)
		s.CheckGet(t, "aap", "442")
	}
}

func TestGetSet(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// Existing key
	{
		s.Set("foo", "bar")
		v, err := redis.String(c.Do("GETSET", "foo", "baz"))
		ok(t, err)
		equals(t, "bar", v)
		s.CheckGet(t, "foo", "baz")
	}

	// New key
	{
		v, err := c.Do("GETSET", "bar", "bak")
		ok(t, err)
		equals(t, nil, v)
		s.CheckGet(t, "bar", "bak")
	}

	// TTL needs to be cleared
	{
		s.Set("one", "two")
		s.SetExpire("one", 1234)
		v, err := redis.String(c.Do("GETSET", "one", "three"))
		ok(t, err)
		equals(t, "two", v)
		s.CheckGet(t, "bar", "bak")
		equals(t, 0, s.Expire("one"))
	}

	// Wrong type of existing key
	{
		s.HSet("wrong", "aap", "noot")
		_, err := redis.Int(c.Do("GETSET", "wrong", "key"))
		assert(t, err != nil, "do GETSET error")
	}

	// Wrong usage
	{
		_, err := redis.Int(c.Do("GETSET"))
		assert(t, err != nil, "do GETSET error")
		_, err = redis.Int(c.Do("GETSET", "spurious", "arguments", "here"))
		assert(t, err != nil, "do GETSET error")
	}
}

func TestStrlen(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// Existing key
	{
		s.Set("foo", "bar!")
		v, err := redis.Int(c.Do("STRLEN", "foo"))
		ok(t, err)
		equals(t, 4, v)
	}

	// New key
	{
		v, err := redis.Int(c.Do("STRLEN", "nosuch"))
		ok(t, err)
		equals(t, 0, v)
	}

	// Wrong type of existing key
	{
		s.HSet("wrong", "aap", "noot")
		_, err := redis.Int(c.Do("STRLEN", "wrong"))
		assert(t, err != nil, "do STRLEN error")
	}

	// Wrong usage
	{
		_, err := redis.Int(c.Do("STRLEN"))
		assert(t, err != nil, "do STRLEN error")
		_, err = redis.Int(c.Do("STRLEN", "spurious", "arguments"))
		assert(t, err != nil, "do STRLEN error")
	}
}

func TestAppend(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// Existing key
	{
		s.Set("foo", "bar!")
		v, err := redis.Int(c.Do("APPEND", "foo", "morebar"))
		ok(t, err)
		equals(t, 11, v)
	}

	// New key
	{
		v, err := redis.Int(c.Do("APPEND", "bar", "was empty"))
		ok(t, err)
		equals(t, 9, v)
	}

	// Wrong type of existing key
	{
		s.HSet("wrong", "aap", "noot")
		_, err := redis.Int(c.Do("APPEND", "wrong", "type"))
		assert(t, err != nil, "do APPEND error")
	}

	// Wrong usage
	{
		_, err := redis.Int(c.Do("APPEND"))
		assert(t, err != nil, "do APPEND error")
		_, err = redis.Int(c.Do("APPEND", "missing"))
		assert(t, err != nil, "do APPEND error")
		_, err = redis.Int(c.Do("APPEND", "spurious", "arguments", "!"))
		assert(t, err != nil, "do APPEND error")
	}
}

func TestGetrange(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	{
		s.Set("foo", "abcdefg")
		type tc struct {
			s   int
			e   int
			res string
		}
		for _, p := range []tc{
			{0, 0, "a"},
			{0, 3, "abcd"},
			{0, 7, "abcdefg"},
			{0, 100, "abcdefg"},
			{1, 2, "bc"},
			{1, 100, "bcdefg"},
			{-4, -2, "def"},
			{0, -1, "abcdefg"},
			{0, -2, "abcdef"},
			{0, -100, "a"}, // Redis is funny
			{-2, 2, ""},
		} {
			{
				v, err := redis.String(c.Do("GETRANGE", "foo", p.s, p.e))
				ok(t, err)
				equals(t, p.res, v)
			}
		}
	}

	// New key
	{
		v, err := redis.String(c.Do("GETRANGE", "bar", 0, 4))
		ok(t, err)
		equals(t, "", v)
	}

	// Wrong type of existing key
	{
		s.HSet("wrong", "aap", "noot")
		_, err := redis.Int(c.Do("GETRANGE", "wrong", 0, 0))
		assert(t, err != nil, "do APPEND error")
	}

	// Wrong usage
	{
		_, err := redis.Int(c.Do("GETRANGE"))
		assert(t, err != nil, "do GETRANGE error")
		_, err = redis.Int(c.Do("GETRANGE", "missing"))
		assert(t, err != nil, "do GETRANGE error")
		_, err = redis.Int(c.Do("GETRANGE", "many", "spurious", "arguments", "!"))
		assert(t, err != nil, "do GETRANGE error")
		_, err = redis.Int(c.Do("GETRANGE", "many", "noint", 12))
		assert(t, err != nil, "do GETRANGE error")
		_, err = redis.Int(c.Do("GETRANGE", "many", 12, "noint"))
		assert(t, err != nil, "do GETRANGE error")
	}
}

func TestSetrange(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// Simple case
	{
		s.Set("foo", "abcdefg")
		v, err := redis.Int(c.Do("SETRANGE", "foo", 1, "bar"))
		ok(t, err)
		equals(t, 7, v)
		s.CheckGet(t, "foo", "abarefg")
	}
	// Non existing key
	{
		v, err := redis.Int(c.Do("SETRANGE", "nosuch", 3, "bar"))
		ok(t, err)
		equals(t, 6, v)
		s.CheckGet(t, "nosuch", "\x00\x00\x00bar")
	}

	// Wrong type of existing key
	{
		s.HSet("wrong", "aap", "noot")
		_, err := redis.Int(c.Do("SETRANGE", "wrong", 0, "aap"))
		assert(t, err != nil, "do SETRANGE error")
	}

	// Wrong usage
	{
		_, err := redis.Int(c.Do("SETRANGE"))
		assert(t, err != nil, "do SETRANGE error")
		_, err = redis.Int(c.Do("SETRANGE", "missing"))
		assert(t, err != nil, "do SETRANGE error")
		_, err = redis.Int(c.Do("SETRANGE", "missing", 1))
		assert(t, err != nil, "do SETRANGE error")
		_, err = redis.Int(c.Do("SETRANGE", "key", "noint", ""))
		assert(t, err != nil, "do SETRANGE error")
		_, err = redis.Int(c.Do("SETRANGE", "key", -1, ""))
		assert(t, err != nil, "do SETRANGE error")
		_, err = redis.Int(c.Do("SETRANGE", "many", 12, "keys", "here"))
		assert(t, err != nil, "do SETRANGE error")
	}
}

func TestBitcount(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	{
		s.Set("countme", "a") // 'a' is 0x1100001
		v, err := redis.Int(c.Do("BITCOUNT", "countme"))
		ok(t, err)
		equals(t, 3, v)

		s.Set("countme", "aaaaa") // 'a' is 0x1100001
		v, err = redis.Int(c.Do("BITCOUNT", "countme"))
		ok(t, err)
		equals(t, 3*5, v)
	}
	// Non-existing
	{
		v, err := redis.Int(c.Do("BITCOUNT", "nosuch"))
		ok(t, err)
		equals(t, 0, v)
	}

	{
		// a: 0x1100001 - 3
		// b: 0x1100010 - 3
		// c: 0x1100011 - 4
		// d: 0x1100100 - 3
		s.Set("foo", "abcd")
		type tc struct {
			s   int
			e   int
			res int
		}
		for _, p := range []tc{
			{0, 0, 3},   // "a"
			{0, 3, 13},  // "abcd"
			{-2, -2, 4}, // "c"
		} {
			{
				v, err := redis.Int(c.Do("BITCOUNT", "foo", p.s, p.e))
				ok(t, err)
				equals(t, p.res, v)
			}
		}
	}

	// Wrong type of existing key
	{
		s.HSet("wrong", "aap", "noot")
		_, err := redis.Int(c.Do("BITCOUNT", "wrong"))
		// ok(t, err)
		// equals(t, 0, v)
		assert(t, err != nil, "do BITCOUNT error")
	}

	// Wrong usage
	{
		_, err := redis.Int(c.Do("BITCOUNT"))
		assert(t, err != nil, "do BITCOUNT error")
		// _, err = redis.Int(c.Do("BITCOUNT", "many", "spurious", "arguments", "!"))
		// assert(t, err != nil, "do BITCOUNT error")
		_, err = redis.Int(c.Do("BITCOUNT", "many", "noint", 12))
		assert(t, err != nil, "do BITCOUNT error")
		_, err = redis.Int(c.Do("BITCOUNT", "many", 12, "noint"))
		assert(t, err != nil, "do BITCOUNT error")
	}
}

func TestBitop(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	{
		and := func(a, b byte) byte { return a & b }
		equals(t, []byte("`"), sliceBinOp(and, []byte("a"), []byte("b")))
		equals(t, []byte("`\000\000"), sliceBinOp(and, []byte("aaa"), []byte("b")))
		equals(t, []byte("`\000\000"), sliceBinOp(and, []byte("a"), []byte("bbb")))
		equals(t, []byte("``\000"), sliceBinOp(and, []byte("aa"), []byte("bbb")))
	}

	// Single char AND
	{
		s.Set("a", "a") // 'a' is 0x1100001
		s.Set("b", "b") // 'b' is 0x1100010
		v, err := redis.Int(c.Do("BITOP", "AND", "bitand", "a", "b"))
		ok(t, err)
		equals(t, 1, v) // Length of the longest key
		s.CheckGet(t, "bitand", "`")
	}
	// Multi char AND
	{
		s.Set("a", "aa")   // 'a' is 0x1100001
		s.Set("b", "bbbb") // 'b' is 0x1100010
		v, err := redis.Int(c.Do("BITOP", "AND", "bitand", "a", "b"))
		ok(t, err)
		equals(t, 4, v) // Length of the longest key
		s.CheckGet(t, "bitand", "``\000\000")
	}

	// Multi char OR
	{
		s.Set("a", "aa")   // 'a' is 0x1100001
		s.Set("b", "bbbb") // 'b' is 0x1100010
		v, err := redis.Int(c.Do("BITOP", "OR", "bitor", "a", "b"))
		ok(t, err)
		equals(t, 4, v) // Length of the longest key
		s.CheckGet(t, "bitor", "ccbb")
	}

	// Multi char XOR
	{
		s.Set("a", "aa")   // 'a' is 0x1100001
		s.Set("b", "bbbb") // 'b' is 0x1100010
		v, err := redis.Int(c.Do("BITOP", "XOR", "bitxor", "a", "b"))
		ok(t, err)
		equals(t, 4, v) // Length of the longest key
		s.CheckGet(t, "bitxor", "\x03\x03bb")
	}

	// Guess who's NOT like the other ops?
	{
		s.Set("a", "aa") // 'a' is 0x1100001
		v, err := redis.Int(c.Do("BITOP", "NOT", "not", "a"))
		ok(t, err)
		equals(t, 2, v) // Length of the key
		s.CheckGet(t, "not", "\x9e\x9e")
	}

	// Single argument. Works, just an roundabout copy.
	{
		s.Set("a", "a") // 'a' is 0x1100001
		v, err := redis.Int(c.Do("BITOP", "AND", "copy", "a"))
		ok(t, err)
		equals(t, 1, v) // Length of the longest key
		s.CheckGet(t, "copy", "a")
	}

	// Wrong type of existing key
	{
		s.HSet("wrong", "aap", "noot")
		_, err := redis.Int(c.Do("BITOP", "AND", "wrong"))
		assert(t, err != nil, "do AND error")
	}

	// Wrong usage
	{
		_, err := redis.Int(c.Do("BITOP"))
		assert(t, err != nil, "do BITOP error")
		_, err = redis.Int(c.Do("BITOP", "AND"))
		assert(t, err != nil, "do BITOP error")
		_, err = redis.Int(c.Do("BITOP", "WHAT"))
		assert(t, err != nil, "do BITOP error")
		_, err = redis.Int(c.Do("BITOP", "NOT"))
		assert(t, err != nil, "do BITOP error")
		_, err = redis.Int(c.Do("BITOP", "NOT", "foo", "bar", "baz"))
		assert(t, err != nil, "do BITOP error")
	}
}

func TestBitpos(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	{
		s.Set("findme", "\xff\xf0\x00")
		v, err := redis.Int(c.Do("BITPOS", "findme", 0))
		ok(t, err)
		equals(t, 12, v)
		v, err = redis.Int(c.Do("BITPOS", "findme", 0, 1))
		ok(t, err)
		equals(t, 12, v)
		v, err = redis.Int(c.Do("BITPOS", "findme", 0, 1, 1))
		ok(t, err)
		equals(t, 12, v)

		v, err = redis.Int(c.Do("BITPOS", "findme", 1))
		ok(t, err)
		equals(t, 0, v)
		v, err = redis.Int(c.Do("BITPOS", "findme", 1, 1))
		ok(t, err)
		equals(t, 8, v)
		v, err = redis.Int(c.Do("BITPOS", "findme", 1, 1, 2))
		ok(t, err)
		equals(t, 8, v)

		v, err = redis.Int(c.Do("BITPOS", "findme", 1, 10000))
		ok(t, err)
		equals(t, -1, v)
	}

	// Only zeros.
	{
		s.Set("zero", "\x00\x00")
		v, err := redis.Int(c.Do("BITPOS", "zero", 1))
		ok(t, err)
		equals(t, -1, v)
		v, err = redis.Int(c.Do("BITPOS", "zero", 0))
		ok(t, err)
		equals(t, 0, v)

		// -end is ok
		v, err = redis.Int(c.Do("BITPOS", "zero", 0, 0, -100))
		ok(t, err)
		equals(t, -1, v)
	}

	// Only ones.
	{
		s.Set("one", "\xff\xff")
		v, err := redis.Int(c.Do("BITPOS", "one", 1))
		ok(t, err)
		equals(t, 0, v)
		v, err = redis.Int(c.Do("BITPOS", "one", 1, 1))
		ok(t, err)
		equals(t, 8, v)
		v, err = redis.Int(c.Do("BITPOS", "one", 1, 2))
		ok(t, err)
		equals(t, -1, v)
		v, err = redis.Int(c.Do("BITPOS", "one", 0))
		ok(t, err)
		equals(t, 16, v) // Special case
		v, err = redis.Int(c.Do("BITPOS", "one", 0, 1))
		ok(t, err)
		equals(t, 16, v) // Special case
		v, err = redis.Int(c.Do("BITPOS", "one", 0, 0, 1))
		ok(t, err)
		equals(t, -1, v) // Counter the special case
	}

	// Non-existing
	{
		v, err := redis.Int(c.Do("BITPOS", "nosuch", 1))
		ok(t, err)
		equals(t, -1, v)
		v, err = redis.Int(c.Do("BITPOS", "nosuch", 0))
		ok(t, err)
		equals(t, 0, v) // that makes no sense.
	}

	// Empty string
	{
		s.Set("empty", "")
		v, err := redis.Int(c.Do("BITPOS", "empty", 1))
		ok(t, err)
		equals(t, -1, v)
		v, err = redis.Int(c.Do("BITPOS", "empty", 0))
		ok(t, err)
		equals(t, 0, v)
	}

	// Wrong type of existing key
	{
		s.HSet("wrong", "aap", "noot")
		_, err := redis.Int(c.Do("BITPOS", "wrong", 1))
		assert(t, err != nil, "do BITPOS error")
	}

	// Wrong usage
	{
		_, err := redis.Int(c.Do("BITPOS"))
		assert(t, err != nil, "do BITPOS error")
		_, err = redis.Int(c.Do("BITPOS", "many", "spurious", "arguments", "!"))
		assert(t, err != nil, "do BITPOS error")
		_, err = redis.Int(c.Do("BITPOS", "many", "noint"))
		assert(t, err != nil, "do BITPOS error")
		_, err = redis.Int(c.Do("BITPOS", "many"))
		assert(t, err != nil, "do BITPOS error")
	}
}

func TestGetbit(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	{
		s.Set("findme", "\x08")
		v, err := redis.Int(c.Do("GETBIT", "findme", 0))
		ok(t, err)
		equals(t, 0, v)
		v, err = redis.Int(c.Do("GETBIT", "findme", 4))
		ok(t, err)
		equals(t, 1, v)
		v, err = redis.Int(c.Do("GETBIT", "findme", 5))
		ok(t, err)
		equals(t, 0, v)
	}

	// Non-existing
	{
		v, err := redis.Int(c.Do("GETBIT", "nosuch", 1))
		ok(t, err)
		equals(t, 0, v)
		v, err = redis.Int(c.Do("GETBIT", "nosuch", 1000))
		ok(t, err)
		equals(t, 0, v)
	}

	// Wrong type of existing key
	{
		s.HSet("wrong", "aap", "noot")
		_, err := redis.Int(c.Do("GETBIT", "wrong", 1))
		assert(t, err != nil, "do GETBIT error")
	}

	// Wrong usage
	{
		_, err := redis.Int(c.Do("GETBIT", "foo"))
		assert(t, err != nil, "do GETBIT error")
		_, err = redis.Int(c.Do("GETBIT", "spurious", "arguments", "!"))
		assert(t, err != nil, "do GETBIT error")
		_, err = redis.Int(c.Do("GETBIT", "many", "noint"))
		assert(t, err != nil, "do GETBIT error")
	}
}

func TestSetbit(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	{
		s.Set("findme", "\x08")
		v, err := redis.Int(c.Do("SETBIT", "findme", 4, 0))
		ok(t, err)
		equals(t, 1, v)
		s.CheckGet(t, "findme", "\x00")

		v, err = redis.Int(c.Do("SETBIT", "findme", 4, 1))
		ok(t, err)
		equals(t, 0, v)
		s.CheckGet(t, "findme", "\x08")
	}

	// Non-existing
	{
		v, err := redis.Int(c.Do("SETBIT", "nosuch", 0, 1))
		ok(t, err)
		equals(t, 0, v)
		s.CheckGet(t, "nosuch", "\x80")
	}

	// Too short
	{
		s.Set("short", "\x00\x00")
		v, err := redis.Int(c.Do("SETBIT", "short", 24, 0))
		ok(t, err)
		equals(t, 0, v)
		s.CheckGet(t, "short", "\x00\x00\x00\x00")
		v, err = redis.Int(c.Do("SETBIT", "short", 32, 1))
		ok(t, err)
		equals(t, 0, v)
		s.CheckGet(t, "short", "\x00\x00\x00\x00\x80")
	}

	// Wrong type of existing key
	{
		s.HSet("wrong", "aap", "noot")
		_, err := redis.Int(c.Do("SETBIT", "wrong", 0, 1))
		assert(t, err != nil, "do SETBIT error")
	}

	// Wrong usage
	{
		_, err := redis.Int(c.Do("SETBIT", "foo"))
		assert(t, err != nil, "do SETBIT error")
		_, err = redis.Int(c.Do("SETBIT", "spurious", "arguments", "!"))
		assert(t, err != nil, "do SETBIT error")
		_, err = redis.Int(c.Do("SETBIT", "many", "noint", 1))
		assert(t, err != nil, "do SETBIT error")
		_, err = redis.Int(c.Do("SETBIT", "many", 1, "noint"))
		assert(t, err != nil, "do SETBIT error")
		_, err = redis.Int(c.Do("SETBIT", "many", -3, 0))
		assert(t, err != nil, "do SETBIT error")
		_, err = redis.Int(c.Do("SETBIT", "many", 3, 2))
		assert(t, err != nil, "do SETBIT error")
	}
}

func TestMsetnx(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	{
		v, err := redis.Int(c.Do("MSETNX", "aap", "noot", "mies", "vuur"))
		ok(t, err)
		equals(t, 1, v)
		s.CheckGet(t, "aap", "noot")
		s.CheckGet(t, "mies", "vuur")
	}

	// A key exists.
	{
		v, err := redis.Int(c.Do("MSETNX", "noaap", "noot", "mies", "vuur!"))
		ok(t, err)
		equals(t, 0, v)
		equals(t, false, s.Exists("noaap"))
		s.CheckGet(t, "aap", "noot")
		s.CheckGet(t, "mies", "vuur")
	}

	// Other type of existing key
	{
		s.HSet("one", "two", "three")
		v, err := redis.Int(c.Do("MSETNX", "one", "two", "three", "four!"))
		ok(t, err)
		equals(t, 0, v)
		equals(t, false, s.Exists("three"))
	}

	// Wrong usage
	{
		_, err := redis.Int(c.Do("MSETNX", "foo"))
		assert(t, err != nil, "do MSETNX error")
		_, err = redis.Int(c.Do("MSETNX", "odd", "arguments", "!"))
		assert(t, err != nil, "do MSETNX error")
		_, err = redis.Int(c.Do("MSETNX"))
		assert(t, err != nil, "do MSETNX error")
	}
}

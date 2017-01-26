package miniredis

import (
	"sort"
	"testing"

	"github.com/garyburd/redigo/redis"
)

// Test Hash.
func TestHash(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	{
		b, err := redis.Int(c.Do("HSET", "aap", "noot", "mies"))
		ok(t, err)
		equals(t, 1, b) // New field.
	}

	{
		v, err := redis.String(c.Do("HGET", "aap", "noot"))
		ok(t, err)
		equals(t, "mies", v)
		equals(t, "mies", s.HGet("aap", "noot"))
	}

	{
		b, err := redis.Int(c.Do("HSET", "aap", "noot", "mies"))
		ok(t, err)
		equals(t, 0, b) // Existing field.
	}

	// Wrong type of key
	{
		_, err := redis.String(c.Do("SET", "foo", "bar"))
		ok(t, err)
		_, err = redis.Int(c.Do("HSET", "foo", "noot", "mies"))
		assert(t, err != nil, "HSET error")
	}

	// hash exists, key doesn't.
	{
		b, err := c.Do("HGET", "aap", "nosuch")
		ok(t, err)
		equals(t, nil, b)
	}

	// hash doesn't exists.
	{
		b, err := c.Do("HGET", "nosuch", "nosuch")
		ok(t, err)
		equals(t, nil, b)
		equals(t, "", s.HGet("nosuch", "nosuch"))
	}

	// HGET on wrong type
	{
		_, err := redis.Int(c.Do("HGET", "aap"))
		assert(t, err != nil, "HGET error")
	}

	// Direct HSet()
	{
		s.HSet("wim", "zus", "jet")
		v, err := redis.String(c.Do("HGET", "wim", "zus"))
		ok(t, err)
		equals(t, "jet", v)
	}
}

func TestHashSetNX(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// New Hash
	v, err := redis.Int(c.Do("HSETNX", "wim", "zus", "jet"))
	ok(t, err)
	equals(t, 1, v)

	v, err = redis.Int(c.Do("HSETNX", "wim", "zus", "jet"))
	ok(t, err)
	equals(t, 0, v)

	// Just a new key
	v, err = redis.Int(c.Do("HSETNX", "wim", "aap", "noot"))
	ok(t, err)
	equals(t, 1, v)

	// Wrong key type
	s.Set("foo", "bar")
	_, err = redis.Int(c.Do("HSETNX", "foo", "nosuch", "nosuch"))
	assert(t, err != nil, "no HSETNX error")
}

func TestHashMSet(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// New Hash
	{
		v, err := redis.String(c.Do("HMSET", "hash", "wim", "zus", "jet", "vuur"))
		ok(t, err)
		equals(t, "OK", v)

		equals(t, "zus", s.HGet("hash", "wim"))
		equals(t, "vuur", s.HGet("hash", "jet"))
	}

	// Doesn't touch ttl.
	{
		s.SetExpire("hash", 999)
		v, err := redis.String(c.Do("HMSET", "hash", "gijs", "lam"))
		ok(t, err)
		equals(t, "OK", v)
		equals(t, 999, s.Expire("hash"))
	}

	{
		// Wrong key type
		s.Set("str", "value")
		_, err = redis.Int(c.Do("HMSET", "str", "key", "value"))
		assert(t, err != nil, "no HSETerror")
		// Usage error
		_, err = redis.Int(c.Do("HMSET", "str"))
		assert(t, err != nil, "no HSETerror")
		_, err = redis.Int(c.Do("HMSET", "str", "odd"))
		assert(t, err != nil, "no HSETerror")
		_, err = redis.Int(c.Do("HMSET", "str", "key", "value", "odd"))
		assert(t, err != nil, "no HSETerror")
	}
}

func TestHashDel(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.HSet("wim", "zus", "jet")
	s.HSet("wim", "teun", "vuur")
	s.HSet("wim", "gijs", "lam")
	s.HSet("wim", "kees", "bok")
	v, err := redis.Int(c.Do("HDEL", "wim", "zus", "gijs"))
	ok(t, err)
	equals(t, 2, v)

	v, err = redis.Int(c.Do("HDEL", "wim", "nosuch"))
	ok(t, err)
	equals(t, 0, v)

	// Deleting all makes the key disappear
	v, err = redis.Int(c.Do("HDEL", "wim", "teun", "kees"))
	ok(t, err)
	equals(t, 2, v)
	assert(t, !s.Exists("wim"), "no more wim key")

	// Key doesn't exists.
	v, err = redis.Int(c.Do("HDEL", "nosuch", "nosuch"))
	ok(t, err)
	equals(t, 0, v)

	// Wrong key type
	s.Set("foo", "bar")
	_, err = redis.Int(c.Do("HDEL", "foo", "nosuch"))
	assert(t, err != nil, "no HDEL error")

	// Direct HDel()
	s.HSet("aap", "noot", "mies")
	s.HDel("aap", "noot")
	equals(t, "", s.HGet("aap", "noot"))
}

func TestHashExists(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.HSet("wim", "zus", "jet")
	s.HSet("wim", "teun", "vuur")
	v, err := redis.Int(c.Do("HEXISTS", "wim", "zus"))
	ok(t, err)
	equals(t, 1, v)

	v, err = redis.Int(c.Do("HEXISTS", "wim", "nosuch"))
	ok(t, err)
	equals(t, 0, v)

	v, err = redis.Int(c.Do("HEXISTS", "nosuch", "nosuch"))
	ok(t, err)
	equals(t, 0, v)

	// Wrong key type
	s.Set("foo", "bar")
	_, err = redis.Int(c.Do("HEXISTS", "foo", "nosuch"))
	assert(t, err != nil, "no HDEL error")
}

func TestHashGetall(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.HSet("wim", "zus", "jet")
	s.HSet("wim", "teun", "vuur")
	s.HSet("wim", "gijs", "lam")
	s.HSet("wim", "kees", "bok")
	v, err := redis.Strings(c.Do("HGETALL", "wim"))
	ok(t, err)
	equals(t, 8, len(v))
	d := map[string]string{}
	for len(v) > 0 {
		d[v[0]] = v[1]
		v = v[2:]
	}
	equals(t, map[string]string{
		"zus":  "jet",
		"teun": "vuur",
		"gijs": "lam",
		"kees": "bok",
	}, d)

	v, err = redis.Strings(c.Do("HGETALL", "nosuch"))
	ok(t, err)
	equals(t, 0, len(v))

	// Wrong key type
	s.Set("foo", "bar")
	_, err = redis.Int(c.Do("HGETALL", "foo"))
	assert(t, err != nil, "no HGETALL error")
}

func TestHashKeys(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.HSet("wim", "zus", "jet")
	s.HSet("wim", "teun", "vuur")
	s.HSet("wim", "gijs", "lam")
	s.HSet("wim", "kees", "bok")
	{
		v, err := redis.Strings(c.Do("HKEYS", "wim"))
		ok(t, err)
		equals(t, 4, len(v))
		sort.Strings(v)
		equals(t, []string{
			"gijs",
			"kees",
			"teun",
			"zus",
		}, v)
	}

	// Direct command
	{
		direct, err := s.HKeys("wim")
		ok(t, err)
		sort.Strings(direct)
		equals(t, []string{
			"gijs",
			"kees",
			"teun",
			"zus",
		}, direct)
		_, err = s.HKeys("nosuch")
		equals(t, err, ErrKeyNotFound)
	}

	v, err := redis.Strings(c.Do("HKEYS", "nosuch"))
	ok(t, err)
	equals(t, 0, len(v))

	// Wrong key type
	s.Set("foo", "bar")
	_, err = redis.Int(c.Do("HKEYS", "foo"))
	assert(t, err != nil, "no HKEYS error")
}

func TestHashValues(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.HSet("wim", "zus", "jet")
	s.HSet("wim", "teun", "vuur")
	s.HSet("wim", "gijs", "lam")
	s.HSet("wim", "kees", "bok")
	v, err := redis.Strings(c.Do("HVALS", "wim"))
	ok(t, err)
	equals(t, 4, len(v))
	sort.Strings(v)
	equals(t, []string{
		"bok",
		"jet",
		"lam",
		"vuur",
	}, v)

	v, err = redis.Strings(c.Do("HVALS", "nosuch"))
	ok(t, err)
	equals(t, 0, len(v))

	// Wrong key type
	s.Set("foo", "bar")
	_, err = redis.Int(c.Do("HVALS", "foo"))
	assert(t, err != nil, "no HVALS error")
}

func TestHashLen(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.HSet("wim", "zus", "jet")
	s.HSet("wim", "teun", "vuur")
	s.HSet("wim", "gijs", "lam")
	s.HSet("wim", "kees", "bok")
	v, err := redis.Int(c.Do("HLEN", "wim"))
	ok(t, err)
	equals(t, 4, v)

	v, err = redis.Int(c.Do("HLEN", "nosuch"))
	ok(t, err)
	equals(t, 0, v)

	// Wrong key type
	s.Set("foo", "bar")
	_, err = redis.Int(c.Do("HLEN", "foo"))
	assert(t, err != nil, "no HLEN error")
}

func TestHashMget(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.HSet("wim", "zus", "jet")
	s.HSet("wim", "teun", "vuur")
	s.HSet("wim", "gijs", "lam")
	s.HSet("wim", "kees", "bok")
	v, err := redis.Values(c.Do("HMGET", "wim", "zus", "nosuch", "kees"))
	ok(t, err)
	equals(t, 3, len(v))
	equals(t, "jet", string(v[0].([]byte)))
	equals(t, nil, v[1])
	equals(t, "bok", string(v[2].([]byte)))

	v, err = redis.Values(c.Do("HMGET", "nosuch", "zus", "kees"))
	ok(t, err)
	equals(t, 2, len(v))
	equals(t, nil, v[0])
	equals(t, nil, v[1])

	// Wrong key type
	s.Set("foo", "bar")
	_, err = redis.Int(c.Do("HMGET", "foo", "bar"))
	assert(t, err != nil, "no HMGET error")
}

func TestHashIncrby(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// New key
	{
		v, err := redis.Int(c.Do("HINCRBY", "hash", "field", 1))
		ok(t, err)
		equals(t, 1, v)
	}

	// Existing key
	{
		v, err := redis.Int(c.Do("HINCRBY", "hash", "field", 100))
		ok(t, err)
		equals(t, 101, v)
	}

	// Minus works.
	{
		v, err := redis.Int(c.Do("HINCRBY", "hash", "field", -12))
		ok(t, err)
		equals(t, 101-12, v)
	}

	// Direct usage
	s.HIncr("hash", "field", -3)
	equals(t, "86", s.HGet("hash", "field"))

	// Error cases.
	{
		// Wrong key type
		s.Set("str", "cake")
		_, err = redis.Values(c.Do("HINCRBY", "str", "case", 4))
		assert(t, err != nil, "no HINCRBY error")

		_, err = redis.Values(c.Do("HINCRBY", "str", "case", "foo"))
		assert(t, err != nil, "no HINCRBY error")

		_, err = redis.Values(c.Do("HINCRBY", "str"))
		assert(t, err != nil, "no HINCRBY error")
	}
}

func TestHashIncrbyfloat(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// Existing key
	{
		s.HSet("hash", "field", "12")
		v, err := redis.Float64(c.Do("HINCRBYFLOAT", "hash", "field", "400.12"))
		ok(t, err)
		equals(t, 412.12, v)
		equals(t, "412.12", s.HGet("hash", "field"))
	}

	// Existing key, not a number
	{
		s.HSet("hash", "field", "noint")
		_, err := redis.Float64(c.Do("HINCRBYFLOAT", "hash", "field", "400"))
		assert(t, err != nil, "do HINCRBYFLOAT error")
	}

	// New key
	{
		v, err := redis.Float64(c.Do("HINCRBYFLOAT", "hash", "newfield", "40.33"))
		ok(t, err)
		equals(t, 40.33, v)
		equals(t, "40.33", s.HGet("hash", "newfield"))
	}

	// Direct usage
	{
		s.HSet("hash", "field", "500.1")
		f, err := s.HIncrfloat("hash", "field", 12)
		ok(t, err)
		equals(t, 512.1, f)
		equals(t, "512.1", s.HGet("hash", "field"))
	}

	// Wrong type of existing key
	{
		s.Set("wrong", "type")
		_, err := redis.Int(c.Do("HINCRBYFLOAT", "wrong", "type", "400"))
		assert(t, err != nil, "do HINCRBYFLOAT error")
	}

	// Wrong usage
	{
		_, err := redis.Int(c.Do("HINCRBYFLOAT"))
		assert(t, err != nil, "do HINCRBYFLOAT error")
		_, err = redis.Int(c.Do("HINCRBYFLOAT", "wrong"))
		assert(t, err != nil, "do HINCRBYFLOAT error")
		_, err = redis.Int(c.Do("HINCRBYFLOAT", "wrong", "value"))
		assert(t, err != nil, "do HINCRBYFLOAT error")
		_, err = redis.Int(c.Do("HINCRBYFLOAT", "wrong", "value", "noint"))
		assert(t, err != nil, "do HINCRBYFLOAT error")
		_, err = redis.Int(c.Do("HINCRBYFLOAT", "foo", "bar", 12, "tomanye"))
		assert(t, err != nil, "do HINCRBYFLOAT error")
	}
}

func TestHscan(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// We cheat with hscan. It always returns everything.

	s.HSet("h", "field1", "value1")
	s.HSet("h", "field2", "value2")

	// No problem
	{
		res, err := redis.Values(c.Do("HSCAN", "h", 0))
		ok(t, err)
		equals(t, 2, len(res))

		var c int
		var keys []string
		_, err = redis.Scan(res, &c, &keys)
		ok(t, err)
		equals(t, 0, c)
		equals(t, []string{"field1", "value1", "field2", "value2"}, keys)
	}

	// Invalid cursor
	{
		res, err := redis.Values(c.Do("HSCAN", "h", 42))
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
		res, err := redis.Values(c.Do("HSCAN", "h", 0, "COUNT", 200))
		ok(t, err)
		equals(t, 2, len(res))

		var c int
		var keys []string
		_, err = redis.Scan(res, &c, &keys)
		ok(t, err)
		equals(t, 0, c)
		equals(t, []string{"field1", "value1", "field2", "value2"}, keys)
	}

	// MATCH
	{
		s.HSet("h", "aap", "a")
		s.HSet("h", "noot", "b")
		s.HSet("h", "mies", "m")
		res, err := redis.Values(c.Do("HSCAN", "h", 0, "MATCH", "mi*"))
		ok(t, err)
		equals(t, 2, len(res))

		var c int
		var keys []string
		_, err = redis.Scan(res, &c, &keys)
		ok(t, err)
		equals(t, 0, c)
		equals(t, []string{"mies", "m"}, keys)
	}

	// Wrong usage
	{
		_, err := redis.Int(c.Do("HSCAN"))
		assert(t, err != nil, "do HSCAN error")
		_, err = redis.Int(c.Do("HSCAN", "set"))
		assert(t, err != nil, "do HSCAN error")
		_, err = redis.Int(c.Do("HSCAN", "set", "noint"))
		assert(t, err != nil, "do HSCAN error")
		_, err = redis.Int(c.Do("HSCAN", "set", 1, "MATCH"))
		assert(t, err != nil, "do HSCAN error")
		_, err = redis.Int(c.Do("HSCAN", "set", 1, "COUNT"))
		assert(t, err != nil, "do HSCAN error")
		_, err = redis.Int(c.Do("HSCAN", "set", 1, "COUNT", "noint"))
		assert(t, err != nil, "do HSCAN error")
		s.Set("str", "value")
		_, err = redis.Int(c.Do("HSCAN", "str", 1))
		assert(t, err != nil, "do HSCAN error")
	}
}

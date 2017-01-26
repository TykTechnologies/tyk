package miniredis

import (
	"testing"
	"time"

	"github.com/garyburd/redigo/redis"
)

func setup(t *testing.T) (*Miniredis, redis.Conn, func()) {
	s, err := Run()
	ok(t, err)
	c1, err := redis.Dial("tcp", s.Addr())
	ok(t, err)
	return s, c1, func() { s.Close() }
}
func setup2(t *testing.T) (*Miniredis, redis.Conn, redis.Conn, func()) {
	s, err := Run()
	ok(t, err)
	c1, err := redis.Dial("tcp", s.Addr())
	ok(t, err)
	c2, err := redis.Dial("tcp", s.Addr())
	ok(t, err)
	return s, c1, c2, func() { s.Close() }
}

func TestLpush(t *testing.T) {
	s, c, done := setup(t)
	defer done()

	{
		b, err := redis.Int(c.Do("LPUSH", "l", "aap", "noot", "mies"))
		ok(t, err)
		equals(t, 3, b) // New length.

		r, err := redis.Strings(c.Do("LRANGE", "l", "0", "0"))
		ok(t, err)
		equals(t, []string{"mies"}, r)

		r, err = redis.Strings(c.Do("LRANGE", "l", "-1", "-1"))
		ok(t, err)
		equals(t, []string{"aap"}, r)
	}

	// Push more.
	{
		b, err := redis.Int(c.Do("LPUSH", "l", "aap2", "noot2", "mies2"))
		ok(t, err)
		equals(t, 6, b) // New length.

		r, err := redis.Strings(c.Do("LRANGE", "l", "0", "0"))
		ok(t, err)
		equals(t, []string{"mies2"}, r)

		r, err = redis.Strings(c.Do("LRANGE", "l", "-1", "-1"))
		ok(t, err)
		equals(t, []string{"aap"}, r)
	}

	// Direct usage
	{
		l, err := s.Lpush("l2", "a")
		ok(t, err)
		equals(t, 1, l)
		l, err = s.Lpush("l2", "b")
		ok(t, err)
		equals(t, 2, l)
		list, err := s.List("l2")
		ok(t, err)
		equals(t, []string{"b", "a"}, list)

		el, err := s.Lpop("l2")
		ok(t, err)
		equals(t, "b", el)
		el, err = s.Lpop("l2")
		ok(t, err)
		equals(t, "a", el)
		// Key is removed on pop-empty.
		equals(t, false, s.Exists("l2"))
	}

	// Various errors
	{
		_, err := redis.Int(c.Do("LPUSH"))
		assert(t, err != nil, "LPUSH error")
		_, err = redis.Int(c.Do("LPUSH", "l"))
		assert(t, err != nil, "LPUSH error")
		_, err = redis.String(c.Do("SET", "str", "value"))
		ok(t, err)
		_, err = redis.Int(c.Do("LPUSH", "str", "noot", "mies"))
		assert(t, err != nil, "LPUSH error")
	}

}

func TestLpushx(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	{
		b, err := redis.Int(c.Do("LPUSHX", "l", "aap"))
		ok(t, err)
		equals(t, 0, b)
		equals(t, false, s.Exists("l"))

		// Create the list with a normal LPUSH
		b, err = redis.Int(c.Do("LPUSH", "l", "noot"))
		ok(t, err)
		equals(t, 1, b)
		equals(t, true, s.Exists("l"))

		b, err = redis.Int(c.Do("LPUSHX", "l", "mies"))
		ok(t, err)
		equals(t, 2, b)
		equals(t, true, s.Exists("l"))
	}

	// Errors
	{
		_, err = redis.Int(c.Do("LPUSHX"))
		assert(t, err != nil, "LPUSHX error")
		_, err = redis.Int(c.Do("LPUSHX", "l"))
		assert(t, err != nil, "LPUSHX error")
		_, err = redis.Int(c.Do("LPUSHX", "l", "too", "many"))
		assert(t, err != nil, "LPUSHX error")
		_, err := redis.String(c.Do("SET", "str", "value"))
		ok(t, err)
		_, err = redis.Int(c.Do("LPUSHX", "str", "mies"))
		assert(t, err != nil, "LPUSHX error")
	}

}

func TestLpop(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	b, err := redis.Int(c.Do("LPUSH", "l", "aap", "noot", "mies"))
	ok(t, err)
	equals(t, 3, b) // New length.

	// Simple pops.
	{
		el, err := redis.String(c.Do("LPOP", "l"))
		ok(t, err)
		equals(t, "mies", el)

		el, err = redis.String(c.Do("LPOP", "l"))
		ok(t, err)
		equals(t, "noot", el)

		el, err = redis.String(c.Do("LPOP", "l"))
		ok(t, err)
		equals(t, "aap", el)

		// Last element has been popped. Key is gone.
		i, err := redis.Int(c.Do("EXISTS", "l"))
		ok(t, err)
		equals(t, 0, i)

		// Can pop non-existing keys just fine.
		v, err := c.Do("LPOP", "l")
		ok(t, err)
		equals(t, nil, v)
	}
}

func TestRPushPop(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	{
		b, err := redis.Int(c.Do("RPUSH", "l", "aap", "noot", "mies"))
		ok(t, err)
		equals(t, 3, b) // New length.

		r, err := redis.Strings(c.Do("LRANGE", "l", "0", "0"))
		ok(t, err)
		equals(t, []string{"aap"}, r)

		r, err = redis.Strings(c.Do("LRANGE", "l", "-1", "-1"))
		ok(t, err)
		equals(t, []string{"mies"}, r)
	}

	// Push more.
	{
		b, err := redis.Int(c.Do("RPUSH", "l", "aap2", "noot2", "mies2"))
		ok(t, err)
		equals(t, 6, b) // New length.

		r, err := redis.Strings(c.Do("LRANGE", "l", "0", "0"))
		ok(t, err)
		equals(t, []string{"aap"}, r)

		r, err = redis.Strings(c.Do("LRANGE", "l", "-1", "-1"))
		ok(t, err)
		equals(t, []string{"mies2"}, r)
	}

	// Direct usage
	{
		l, err := s.Push("l2", "a")
		ok(t, err)
		equals(t, 1, l)
		l, err = s.Push("l2", "b")
		ok(t, err)
		equals(t, 2, l)
		list, err := s.List("l2")
		ok(t, err)
		equals(t, []string{"a", "b"}, list)

		el, err := s.Pop("l2")
		ok(t, err)
		equals(t, "b", el)
		el, err = s.Pop("l2")
		ok(t, err)
		equals(t, "a", el)
		// Key is removed on pop-empty.
		equals(t, false, s.Exists("l2"))
	}

	// Wrong type of key
	{
		_, err := redis.String(c.Do("SET", "str", "value"))
		ok(t, err)
		_, err = redis.Int(c.Do("RPUSH", "str", "noot", "mies"))
		assert(t, err != nil, "RPUSH error")
	}

}

func TestRpop(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.Push("l", "aap", "noot", "mies")

	// Simple pops.
	{
		el, err := redis.String(c.Do("RPOP", "l"))
		ok(t, err)
		equals(t, "mies", el)

		el, err = redis.String(c.Do("RPOP", "l"))
		ok(t, err)
		equals(t, "noot", el)

		el, err = redis.String(c.Do("RPOP", "l"))
		ok(t, err)
		equals(t, "aap", el)

		// Last element has been popped. Key is gone.
		i, err := redis.Int(c.Do("EXISTS", "l"))
		ok(t, err)
		equals(t, 0, i)

		// Can pop non-existing keys just fine.
		v, err := c.Do("RPOP", "l")
		ok(t, err)
		equals(t, nil, v)
	}
}

func TestLindex(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.Push("l", "aap", "noot", "mies", "vuur")

	{
		el, err := redis.String(c.Do("LINDEX", "l", "0"))
		ok(t, err)
		equals(t, "aap", el)
	}
	{
		el, err := redis.String(c.Do("LINDEX", "l", "1"))
		ok(t, err)
		equals(t, "noot", el)
	}
	{
		el, err := redis.String(c.Do("LINDEX", "l", "3"))
		ok(t, err)
		equals(t, "vuur", el)
	}
	// Too many
	{
		el, err := c.Do("LINDEX", "l", "3000")
		ok(t, err)
		equals(t, nil, el)
	}
	{
		el, err := redis.String(c.Do("LINDEX", "l", "-1"))
		ok(t, err)
		equals(t, "vuur", el)
	}
	{
		el, err := redis.String(c.Do("LINDEX", "l", "-2"))
		ok(t, err)
		equals(t, "mies", el)
	}
	// Too big
	{
		el, err := c.Do("LINDEX", "l", "-400")
		ok(t, err)
		equals(t, nil, el)
	}
	// Non exising key
	{
		el, err := c.Do("LINDEX", "nonexisting", "400")
		ok(t, err)
		equals(t, nil, el)
	}

	// Wrong type of key
	{
		_, err := redis.String(c.Do("SET", "str", "value"))
		ok(t, err)
		_, err = redis.Int(c.Do("LINDEX", "str", "1"))
		assert(t, err != nil, "LINDEX error")
		// Not an integer
		_, err = redis.String(c.Do("LINDEX", "l", "noint"))
		assert(t, err != nil, "LINDEX error")
		// Too many arguments
		_, err = redis.String(c.Do("LINDEX", "str", "l", "foo"))
		assert(t, err != nil, "LINDEX error")
	}
}

func TestLlen(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.Push("l", "aap", "noot", "mies", "vuur")

	{
		el, err := redis.Int(c.Do("LLEN", "l"))
		ok(t, err)
		equals(t, 4, el)
	}

	// Non exising key
	{
		el, err := redis.Int(c.Do("LLEN", "nonexisting"))
		ok(t, err)
		equals(t, 0, el)
	}

	// Wrong type of key
	{
		_, err := redis.String(c.Do("SET", "str", "value"))
		ok(t, err)
		_, err = redis.Int(c.Do("LLEN", "str"))
		assert(t, err != nil, "LLEN error")
		// Too many arguments
		_, err = redis.String(c.Do("LLEN", "too", "many"))
		assert(t, err != nil, "LLEN error")
	}
}

func TestLtrim(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.Push("l", "aap", "noot", "mies", "vuur")

	{
		el, err := redis.String(c.Do("LTRIM", "l", 0, 2))
		ok(t, err)
		equals(t, "OK", el)
		l, err := s.List("l")
		ok(t, err)
		equals(t, []string{"aap", "noot", "mies"}, l)
	}

	// Delete key on empty list
	{
		el, err := redis.String(c.Do("LTRIM", "l", 0, -99))
		ok(t, err)
		equals(t, "OK", el)
		equals(t, false, s.Exists("l"))
	}

	// Non exising key
	{
		el, err := redis.String(c.Do("LTRIM", "nonexisting", 0, 1))
		ok(t, err)
		equals(t, "OK", el)
	}

	// Wrong type of key
	{
		s.Set("str", "string!")
		_, err = redis.Int(c.Do("LTRIM", "str", 0, 1))
		assert(t, err != nil, "LTRIM error")
		// Too many/little/wrong arguments
		_, err = redis.String(c.Do("LTRIM", "l", 1, 2, "toomany"))
		assert(t, err != nil, "LTRIM error")
		_, err = redis.String(c.Do("LTRIM", "l", 1, "noint"))
		assert(t, err != nil, "LTRIM error")
		_, err = redis.String(c.Do("LTRIM", "l", "noint", 1))
		assert(t, err != nil, "LTRIM error")
		_, err = redis.String(c.Do("LTRIM", "l", 1))
		assert(t, err != nil, "LTRIM error")
		_, err = redis.String(c.Do("LTRIM", "l"))
		assert(t, err != nil, "LTRIM error")
		_, err = redis.String(c.Do("LTRIM"))
		assert(t, err != nil, "LTRIM error")
	}
}

func TestLrem(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// Reverse
	{
		s.Push("l", "aap", "noot", "mies", "vuur", "noot", "noot")
		n, err := redis.Int(c.Do("LREM", "l", -1, "noot"))
		ok(t, err)
		equals(t, 1, n)
		l, err := s.List("l")
		ok(t, err)
		equals(t, []string{"aap", "noot", "mies", "vuur", "noot"}, l)
	}
	// Normal
	{
		s.Push("l2", "aap", "noot", "mies", "vuur", "noot", "noot")
		n, err := redis.Int(c.Do("LREM", "l2", 2, "noot"))
		ok(t, err)
		equals(t, 2, n)
		l, err := s.List("l2")
		ok(t, err)
		equals(t, []string{"aap", "mies", "vuur", "noot"}, l)
	}

	// All
	{
		s.Push("l3", "aap", "noot", "mies", "vuur", "noot", "noot")
		n, err := redis.Int(c.Do("LREM", "l3", 0, "noot"))
		ok(t, err)
		equals(t, 3, n)
		l, err := s.List("l3")
		ok(t, err)
		equals(t, []string{"aap", "mies", "vuur"}, l)
	}

	// All
	{
		s.Push("l4", "aap", "noot", "mies", "vuur", "noot", "noot")
		n, err := redis.Int(c.Do("LREM", "l4", 200, "noot"))
		ok(t, err)
		equals(t, 3, n)
		l, err := s.List("l4")
		ok(t, err)
		equals(t, []string{"aap", "mies", "vuur"}, l)
	}

	// Delete key on empty list
	{
		s.Push("l5", "noot", "noot", "noot")
		n, err := redis.Int(c.Do("LREM", "l5", 99, "noot"))
		ok(t, err)
		equals(t, 3, n)
		equals(t, false, s.Exists("l5"))
	}

	// Non exising key
	{
		n, err := redis.Int(c.Do("LREM", "nonexisting", 0, "aap"))
		ok(t, err)
		equals(t, 0, n)
	}

	// Error cases
	{
		_, err = redis.String(c.Do("LREM"))
		assert(t, err != nil, "LREM error")
		_, err = redis.String(c.Do("LREM", "l"))
		assert(t, err != nil, "LREM error")
		_, err = redis.String(c.Do("LREM", "l", 1))
		assert(t, err != nil, "LREM error")
		_, err = redis.String(c.Do("LREM", "l", "noint", "aap"))
		assert(t, err != nil, "LREM error")
		_, err = redis.String(c.Do("LREM", "l", 1, "aap", "toomany"))
		assert(t, err != nil, "LREM error")
		s.Set("str", "string!")
		_, err = redis.Int(c.Do("LREM", "str", 0, "aap"))
		assert(t, err != nil, "LREM error")
	}
}

func TestLset(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.Push("l", "aap", "noot", "mies", "vuur", "noot", "noot")
	// Simple LSET
	{
		n, err := redis.String(c.Do("LSET", "l", 1, "noot!"))
		ok(t, err)
		equals(t, "OK", n)
		l, err := s.List("l")
		ok(t, err)
		equals(t, []string{"aap", "noot!", "mies", "vuur", "noot", "noot"}, l)
	}

	{
		n, err := redis.String(c.Do("LSET", "l", -1, "noot?"))
		ok(t, err)
		equals(t, "OK", n)
		l, err := s.List("l")
		ok(t, err)
		equals(t, []string{"aap", "noot!", "mies", "vuur", "noot", "noot?"}, l)
	}

	// Out of range
	{
		_, err := c.Do("LSET", "l", 10000, "aap")
		assert(t, err != nil, "LSET error")

		_, err = c.Do("LSET", "l", -10000, "aap")
		assert(t, err != nil, "LSET error")
	}

	// Non exising key
	{
		_, err := c.Do("LSET", "nonexisting", 0, "aap")
		assert(t, err != nil, "LSET error")
	}

	// Error cases
	{
		_, err = redis.String(c.Do("LSET"))
		assert(t, err != nil, "LSET error")
		_, err = redis.String(c.Do("LSET", "l"))
		assert(t, err != nil, "LSET error")
		_, err = redis.String(c.Do("LSET", "l", 1))
		assert(t, err != nil, "LSET error")
		_, err = redis.String(c.Do("LSET", "l", "noint", "aap"))
		assert(t, err != nil, "SET error")
		_, err = redis.String(c.Do("LSET", "l", 1, "aap", "toomany"))
		assert(t, err != nil, "LSET error")
		s.Set("str", "string!")
		_, err = redis.Int(c.Do("LSET", "str", 0, "aap"))
		assert(t, err != nil, "LSET error")
	}
}

func TestLinsert(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.Push("l", "aap", "noot", "mies", "vuur", "noot", "end")
	// Before
	{
		n, err := redis.Int(c.Do("LINSERT", "l", "BEFORE", "noot", "!"))
		ok(t, err)
		equals(t, 7, n)
		l, err := s.List("l")
		ok(t, err)
		equals(t, []string{"aap", "!", "noot", "mies", "vuur", "noot", "end"}, l)
	}

	// After
	{
		n, err := redis.Int(c.Do("LINSERT", "l", "AFTER", "noot", "?"))
		ok(t, err)
		equals(t, 8, n)
		l, err := s.List("l")
		ok(t, err)
		equals(t, []string{"aap", "!", "noot", "?", "mies", "vuur", "noot", "end"}, l)
	}

	// Edge case before
	{
		n, err := redis.Int(c.Do("LINSERT", "l", "BEFORE", "aap", "["))
		ok(t, err)
		equals(t, 9, n)
		l, err := s.List("l")
		ok(t, err)
		equals(t, []string{"[", "aap", "!", "noot", "?", "mies", "vuur", "noot", "end"}, l)
	}

	// Edge case after
	{
		n, err := redis.Int(c.Do("LINSERT", "l", "AFTER", "end", "]"))
		ok(t, err)
		equals(t, 10, n)
		l, err := s.List("l")
		ok(t, err)
		equals(t, []string{"[", "aap", "!", "noot", "?", "mies", "vuur", "noot", "end", "]"}, l)
	}

	// Non exising pivot
	{
		n, err := redis.Int(c.Do("LINSERT", "l", "before", "nosuch", "noot"))
		ok(t, err)
		equals(t, -1, n)
	}

	// Non exising key
	{
		n, err := redis.Int(c.Do("LINSERT", "nonexisting", "before", "aap",
			"noot"))
		ok(t, err)
		equals(t, 0, n)
	}

	// Error cases
	{
		_, err = redis.String(c.Do("LINSERT"))
		assert(t, err != nil, "LINSERT error")
		_, err = redis.String(c.Do("LINSERT", "l"))
		assert(t, err != nil, "LINSERT error")
		_, err = redis.String(c.Do("LINSERT", "l", "before"))
		assert(t, err != nil, "LINSERT error")
		_, err = redis.String(c.Do("LINSERT", "l", "before", "value"))
		assert(t, err != nil, "LINSERT error")
		_, err = redis.String(c.Do("LINSERT", "l", "wrong", "value", "value"))
		assert(t, err != nil, "LINSERT error")
		_, err = redis.String(c.Do("LINSERT", "l", "wrong", "value", "value",
			"toomany"))
		assert(t, err != nil, "LINSERT error")
		s.Set("str", "string!")
		_, err = redis.String(c.Do("LINSERT", "str", "before", "value", "value"))
		assert(t, err != nil, "LINSERT error")
	}
}

func TestRpoplpush(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	s.Push("l", "aap", "noot", "mies")
	s.Push("l2", "vuur", "noot", "end")
	{
		n, err := redis.String(c.Do("RPOPLPUSH", "l", "l2"))
		ok(t, err)
		equals(t, "mies", n)
		s.CheckList(t, "l", "aap", "noot")
		s.CheckList(t, "l2", "mies", "vuur", "noot", "end")
	}
	// Again!
	{
		n, err := redis.String(c.Do("RPOPLPUSH", "l", "l2"))
		ok(t, err)
		equals(t, "noot", n)
		s.CheckList(t, "l", "aap")
		s.CheckList(t, "l2", "noot", "mies", "vuur", "noot", "end")
	}
	// Again!
	{
		n, err := redis.String(c.Do("RPOPLPUSH", "l", "l2"))
		ok(t, err)
		equals(t, "aap", n)
		assert(t, !s.Exists("l"), "l exists")
		s.CheckList(t, "l2", "aap", "noot", "mies", "vuur", "noot", "end")
	}

	// Non exising lists
	{
		s.Push("ll", "aap", "noot", "mies")

		n, err := redis.String(c.Do("RPOPLPUSH", "ll", "nosuch"))
		ok(t, err)
		equals(t, "mies", n)
		assert(t, s.Exists("nosuch"), "nosuch exists")
		s.CheckList(t, "ll", "aap", "noot")
		s.CheckList(t, "nosuch", "mies")

		nada, err := c.Do("RPOPLPUSH", "nosuch2", "ll")
		ok(t, err)
		equals(t, nil, nada)
	}

	// Cycle
	{
		s.Push("cycle", "aap", "noot", "mies")

		n, err := redis.String(c.Do("RPOPLPUSH", "cycle", "cycle"))
		ok(t, err)
		equals(t, "mies", n)
		s.CheckList(t, "cycle", "mies", "aap", "noot")
	}

	// Error cases
	{
		s.Push("src", "aap", "noot", "mies")
		_, err = redis.String(c.Do("RPOPLPUSH"))
		assert(t, err != nil, "RPOPLPUSH error")
		_, err = redis.String(c.Do("RPOPLPUSH", "l"))
		assert(t, err != nil, "RPOPLPUSH error")
		_, err = redis.String(c.Do("RPOPLPUSH", "too", "many", "arguments"))
		assert(t, err != nil, "RPOPLPUSH error")
		s.Set("str", "string!")
		_, err = redis.String(c.Do("RPOPLPUSH", "str", "src"))
		assert(t, err != nil, "RPOPLPUSH error")
		_, err = redis.String(c.Do("RPOPLPUSH", "src", "str"))
		assert(t, err != nil, "RPOPLPUSH error")
	}
}

func TestRpushx(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// Simple cases
	{
		// No key key
		i, err := redis.Int(c.Do("RPUSHX", "l", "value"))
		ok(t, err)
		equals(t, 0, i)
		assert(t, !s.Exists("l"), "l doesn't exist")

		s.Push("l", "aap", "noot")

		i, err = redis.Int(c.Do("RPUSHX", "l", "mies"))
		ok(t, err)
		equals(t, 3, i)

		s.CheckList(t, "l", "aap", "noot", "mies")
	}

	// Error cases
	{
		s.Push("src", "aap", "noot", "mies")
		_, err = redis.String(c.Do("RPUSHX"))
		assert(t, err != nil, "RPUSHX error")
		_, err = redis.String(c.Do("RPUSHX", "l"))
		assert(t, err != nil, "RPUSHX error")
		_, err = redis.String(c.Do("RPUSHX", "too", "many", "arguments"))
		assert(t, err != nil, "RPUSHX error")
		s.Set("str", "string!")
		_, err = redis.String(c.Do("RPUSHX", "str", "value"))
		assert(t, err != nil, "RPUSHX error")
	}
}

// execute command in a go routine. Used to test blocking commands.
func goStrings(t *testing.T, c redis.Conn, cmds ...interface{}) <-chan []string {
	var (
		got = make(chan []string, 1)
	)
	go func() {
		res, err := c.Do(cmds[0].(string), cmds[1:]...)
		if err != nil {
			got <- []string{err.Error()}
			return
		}
		if res == nil {
			got <- nil
		} else {
			st, _ := redis.Strings(res, err)
			got <- st
		}
	}()
	return got
}

func TestBrpop(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// Simple cases
	{
		s.Push("ll", "aap", "noot", "mies")
		v, err := redis.Strings(c.Do("BRPOP", "ll", 1))
		ok(t, err)
		equals(t, []string{"ll", "mies"}, v)
	}

	// Error cases
	{
		_, err = redis.String(c.Do("BRPOP"))
		assert(t, err != nil, "BRPOP error")
		_, err = redis.String(c.Do("BRPOP", "key"))
		assert(t, err != nil, "BRPOP error")
		_, err = redis.String(c.Do("BRPOP", "key", -1))
		assert(t, err != nil, "BRPOP error")
		_, err = redis.String(c.Do("BRPOP", "key", "inf"))
		assert(t, err != nil, "BRPOP error")
	}
}

func TestBrpopSimple(t *testing.T) {
	_, c1, c2, done := setup2(t)
	defer done()

	got := goStrings(t, c2, "BRPOP", "mylist", "0")
	time.Sleep(30 * time.Millisecond)

	b, err := redis.Int(c1.Do("RPUSH", "mylist", "e1", "e2", "e3"))
	ok(t, err)
	equals(t, 3, b)

	select {
	case have := <-got:
		equals(t, []string{"mylist", "e3"}, have)
	case <-time.After(500 * time.Millisecond):
		t.Error("BRPOP took too long")
	}
}

func TestBrpopMulti(t *testing.T) {
	_, c1, c2, done := setup2(t)
	defer done()

	got := goStrings(t, c2, "BRPOP", "l1", "l2", "l3", 0)
	_, err := redis.Int(c1.Do("RPUSH", "l0", "e01"))
	ok(t, err)
	_, err = redis.Int(c1.Do("RPUSH", "l2", "e21"))
	ok(t, err)
	_, err = redis.Int(c1.Do("RPUSH", "l3", "e31"))
	ok(t, err)

	select {
	case have := <-got:
		equals(t, []string{"l2", "e21"}, have)
	case <-time.After(500 * time.Millisecond):
		t.Error("BRPOP took too long")
	}

	got = goStrings(t, c2, "BRPOP", "l1", "l2", "l3", 0)
	select {
	case have := <-got:
		equals(t, []string{"l3", "e31"}, have)
	case <-time.After(500 * time.Millisecond):
		t.Error("BRPOP took too long")
	}
}

func TestBrpopTimeout(t *testing.T) {
	_, c, done := setup(t)
	defer done()

	got := goStrings(t, c, "BRPOP", "l1", 1)
	select {
	case have := <-got:
		equals(t, []string(nil), have)
	case <-time.After(1500 * time.Millisecond):
		t.Error("BRPOP took too long")
	}
}

func TestBrpopTx(t *testing.T) {
	// BRPOP in a transaction behaves as if the timeout triggers right away
	m, c, done := setup(t)
	defer done()

	{
		_, err := c.Do("MULTI")
		ok(t, err)
		s, err := redis.String(c.Do("BRPOP", "l1", 3))
		ok(t, err)
		equals(t, "QUEUED", s)
		s, err = redis.String(c.Do("SET", "foo", "bar"))
		ok(t, err)
		equals(t, "QUEUED", s)

		v, err := redis.Values(c.Do("EXEC"))
		ok(t, err)
		equals(t, 2, len(redis.Args(v)))
		equals(t, nil, v[0])
		equals(t, "OK", v[1])
	}

	// Now set something
	m.Push("l1", "e1")

	{
		_, err := c.Do("MULTI")
		ok(t, err)
		s, err := redis.String(c.Do("BRPOP", "l1", 3))
		ok(t, err)
		equals(t, "QUEUED", s)
		s, err = redis.String(c.Do("SET", "foo", "bar"))
		ok(t, err)
		equals(t, "QUEUED", s)

		v, err := redis.Values(c.Do("EXEC"))
		ok(t, err)
		equals(t, 2, len(redis.Args(v)))
		equals(t, "l1", string(v[0].([]interface{})[0].([]uint8)))
		equals(t, "e1", string(v[0].([]interface{})[1].([]uint8)))
		equals(t, "OK", v[1])
	}
}

func TestBlpop(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// Simple cases
	{
		s.Push("ll", "aap", "noot", "mies")
		v, err := redis.Strings(c.Do("BLPOP", "ll", 1))
		ok(t, err)
		equals(t, []string{"ll", "aap"}, v)
	}

	// Error cases
	{
		_, err = redis.String(c.Do("BLPOP"))
		assert(t, err != nil, "BLPOP error")
		_, err = redis.String(c.Do("BLPOP", "key"))
		assert(t, err != nil, "BLPOP error")
		_, err = redis.String(c.Do("BLPOP", "key", -1))
		assert(t, err != nil, "BLPOP error")
		_, err = redis.String(c.Do("BLPOP", "key", "inf"))
		assert(t, err != nil, "BLPOP error")
	}
}

func TestBrpoplpush(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	// Simple cases
	{
		s.Push("l1", "aap", "noot", "mies")
		v, err := redis.String(c.Do("BRPOPLPUSH", "l1", "l2", "1"))
		ok(t, err)
		equals(t, "mies", v)

		lv, err := s.List("l2")
		ok(t, err)
		equals(t, []string{"mies"}, lv)
	}

	// Error cases
	{
		_, err = redis.String(c.Do("BRPOPLPUSH"))
		assert(t, err != nil, "BRPOPLPUSH error")
		_, err = redis.String(c.Do("BRPOPLPUSH", "key"))
		assert(t, err != nil, "BRPOPLPUSH error")
		_, err = redis.String(c.Do("BRPOPLPUSH", "key", "bar"))
		assert(t, err != nil, "BRPOPLPUSH error")
		_, err = redis.String(c.Do("BRPOPLPUSH", "key", "foo", -1))
		assert(t, err != nil, "BRPOPLPUSH error")
		_, err = redis.String(c.Do("BRPOPLPUSH", "key", "foo", "inf"))
		assert(t, err != nil, "BRPOPLPUSH error")
		_, err = redis.String(c.Do("BRPOPLPUSH", "key", "foo", 1, "baz"))
		assert(t, err != nil, "BRPOPLPUSH error")
	}
}

func TestBrpoplpushSimple(t *testing.T) {
	s, c1, c2, done := setup2(t)
	defer done()

	got := make(chan string, 1)
	go func() {
		b, err := redis.String(c2.Do("BRPOPLPUSH", "from", "to", "1"))
		ok(t, err)
		got <- b
	}()

	time.Sleep(30 * time.Millisecond)

	b, err := redis.Int(c1.Do("RPUSH", "from", "e1", "e2", "e3"))
	ok(t, err)
	equals(t, 3, b)

	select {
	case have := <-got:
		equals(t, "e3", have)
	case <-time.After(500 * time.Millisecond):
		t.Error("BRPOP took too long")
	}

	lv, err := s.List("from")
	ok(t, err)
	equals(t, []string{"e1", "e2"}, lv)
	lv, err = s.List("to")
	ok(t, err)
	equals(t, []string{"e3"}, lv)
}

func TestBrpoplpushTimeout(t *testing.T) {
	_, c, done := setup(t)
	defer done()

	got := goStrings(t, c, "BRPOPLPUSH", "l1", "l2", 1)
	select {
	case have := <-got:
		equals(t, []string(nil), have)
	case <-time.After(1500 * time.Millisecond):
		t.Error("BRPOPLPUSH took too long")
	}
}

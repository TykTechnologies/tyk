package miniredis

import (
	"testing"

	"github.com/garyburd/redigo/redis"
)

func TestAuth(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	_, err = c.Do("AUTH", "foo", "bar")
	assert(t, err != nil, "no password set")

	s.RequireAuth("nocomment")
	_, err = c.Do("PING", "foo", "bar")
	assert(t, err != nil, "need AUTH")

	_, err = c.Do("AUTH", "wrongpasswd")
	assert(t, err != nil, "wrong password")

	_, err = c.Do("AUTH", "nocomment")
	ok(t, err)

	_, err = c.Do("PING")
	ok(t, err)
}

func TestEcho(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	r, err := redis.String(c.Do("ECHO", "hello\nworld"))
	ok(t, err)
	equals(t, "hello\nworld", r)
}

func TestSelect(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	_, err = redis.String(c.Do("SET", "foo", "bar"))
	ok(t, err)

	_, err = redis.String(c.Do("SELECT", "5"))
	ok(t, err)

	_, err = redis.String(c.Do("SET", "foo", "baz"))
	ok(t, err)

	// Direct access.
	got, err := s.Get("foo")
	ok(t, err)
	equals(t, "bar", got)
	s.Select(5)
	got, err = s.Get("foo")
	ok(t, err)
	equals(t, "baz", got)

	// Another connection should have its own idea of the db:
	c2, err := redis.Dial("tcp", s.Addr())
	ok(t, err)
	v, err := redis.String(c2.Do("GET", "foo"))
	ok(t, err)
	equals(t, "bar", v)
}

func TestQuit(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()
	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)

	v, err := redis.String(c.Do("QUIT"))
	ok(t, err)
	equals(t, "OK", v)

	v, err = redis.String(c.Do("PING"))
	assert(t, err != nil, "QUIT closed the client")
	equals(t, "", v)
}

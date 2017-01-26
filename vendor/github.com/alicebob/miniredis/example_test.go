package miniredis_test

import (
	"github.com/alicebob/miniredis"
	"github.com/garyburd/redigo/redis"
)

func Example() {
	s, err := miniredis.Run()
	if err != nil {
		panic(err)
	}
	defer s.Close()

	// Configure you application to connect to redis at s.Addr()
	// Any redis client should work, as long as you use redis commands which
	// miniredis implements.
	c, err := redis.Dial("tcp", s.Addr())
	if err != nil {
		panic(err)
	}
	_, err = c.Do("SET", "foo", "bar")
	if err != nil {
		panic(err)
	}

	// You can ask miniredis about keys directly, without going over the network.
	if got, err := s.Get("foo"); err != nil || got != "bar" {
		panic("Didn't get 'bar' back")
	}
	// Or with a DB id
	if _, err := s.DB(42).Get("foo"); err != miniredis.ErrKeyNotFound {
		panic("Didn't use a different DB")
	}
	// Or use a Check* function which Fail()s if the key is not what we expect
	// (checks for existence, key type and the value)
	// s.CheckGet(t, "foo", "bar")

	// Check if there really was only one connection.
	if s.TotalConnectionCount() != 1 {
		panic("Too many connections made")
	}

	// Output:
}

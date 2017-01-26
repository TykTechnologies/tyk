package miniredis

import (
	"testing"

	"github.com/garyburd/redigo/redis"
)

// Test starting/stopping a server
func TestServer(t *testing.T) {
	s, err := Run()
	ok(t, err)
	defer s.Close()

	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)
	_, err = c.Do("PING")
	ok(t, err)

	// A single client
	equals(t, 1, s.CurrentConnectionCount())
	equals(t, 1, s.TotalConnectionCount())
	equals(t, 1, s.CommandCount())
	_, err = c.Do("PING")
	ok(t, err)
	equals(t, 2, s.CommandCount())
}

func TestMultipleServers(t *testing.T) {
	s1, err := Run()
	ok(t, err)
	s2, err := Run()
	ok(t, err)
	if s1.Addr() == s2.Addr() {
		t.Fatal("Non-unique addresses", s1.Addr(), s2.Addr())
	}

	s2.Close()
	s1.Close()
	// Closing multiple times is fine
	go s1.Close()
	go s1.Close()
	s1.Close()
}

func TestRestart(t *testing.T) {
	s, err := Run()
	ok(t, err)
	addr := s.Addr()

	s.Set("color", "red")

	s.Close()
	err = s.Restart()
	ok(t, err)
	if s.Addr() != addr {
		t.Fatal("should be the same address")
	}

	c, err := redis.Dial("tcp", s.Addr())
	ok(t, err)
	_, err = c.Do("PING")
	ok(t, err)

	red, err := redis.String(c.Do("GET", "color"))
	ok(t, err)
	if have, want := red, "red"; have != want {
		t.Errorf("have: %s, want: %s", have, want)
	}
}

func TestDump(t *testing.T) {
	s, err := Run()
	ok(t, err)
	s.Set("aap", "noot")
	s.Set("vuur", "mies")
	s.HSet("ahash", "aap", "noot")
	s.HSet("ahash", "vuur", "mies")
	if have, want := s.Dump(), `- aap
   "noot"
- ahash
   aap: "noot"
   vuur: "mies"
- vuur
   "mies"
`; have != want {
		t.Errorf("have: %q, want: %q", have, want)
	}

	// Tricky whitespace
	s.Select(1)
	s.Set("whitespace", "foo\nbar\tbaz!")
	if have, want := s.Dump(), `- whitespace
   "foo\nbar\tbaz!"
`; have != want {
		t.Errorf("have: %q, want: %q", have, want)
	}

	// Long key
	s.Select(2)
	s.Set("long", "This is a rather long key, with some fox jumping over a fence or something.")
	s.Set("countonme", "0123456789012345678901234567890123456789012345678901234567890123456789")
	s.HSet("hlong", "long", "This is another rather long key, with some fox jumping over a fence or something.")
	if have, want := s.Dump(), `- countonme
   "01234567890123456789012345678901234567890123456789012"...(70)
- hlong
   long: "This is another rather long key, with some fox jumpin"...(81)
- long
   "This is a rather long key, with some fox jumping over"...(75)
`; have != want {
		t.Errorf("have: %q, want: %q", have, want)
	}
}

func TestDumpList(t *testing.T) {
	s, err := Run()
	ok(t, err)
	s.Push("elements", "earth")
	s.Push("elements", "wind")
	s.Push("elements", "fire")
	if have, want := s.Dump(), `- elements
   "earth"
   "wind"
   "fire"
`; have != want {
		t.Errorf("have: %q, want: %q", have, want)
	}
}

func TestDumpSet(t *testing.T) {
	s, err := Run()
	ok(t, err)
	s.SetAdd("elements", "earth")
	s.SetAdd("elements", "wind")
	s.SetAdd("elements", "fire")
	if have, want := s.Dump(), `- elements
   "earth"
   "fire"
   "wind"
`; have != want {
		t.Errorf("have: %q, want: %q", have, want)
	}
}

func TestDumpSortedSet(t *testing.T) {
	s, err := Run()
	ok(t, err)
	s.ZAdd("elements", 2.0, "wind")
	s.ZAdd("elements", 3.0, "earth")
	s.ZAdd("elements", 1.0, "fire")
	if have, want := s.Dump(), `- elements
   1.000000: "fire"
   2.000000: "wind"
   3.000000: "earth"
`; have != want {
		t.Errorf("have: %q, want: %q", have, want)
	}
}

func TestKeysAndFlush(t *testing.T) {
	s, err := Run()
	ok(t, err)
	s.Set("aap", "noot")
	s.Set("vuur", "mies")
	s.Set("muur", "oom")
	s.HSet("hash", "key", "value")
	equals(t, []string{"aap", "hash", "muur", "vuur"}, s.Keys())

	s.Select(1)
	s.Set("1aap", "1noot")
	equals(t, []string{"1aap"}, s.Keys())

	s.Select(0)
	s.FlushDB()
	equals(t, []string{}, s.Keys())
	s.Select(1)
	equals(t, []string{"1aap"}, s.Keys())

	s.Select(0)
	s.FlushAll()
	equals(t, []string{}, s.Keys())
	s.Select(1)
	equals(t, []string{}, s.Keys())
}

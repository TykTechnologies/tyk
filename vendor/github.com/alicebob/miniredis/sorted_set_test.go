package miniredis

import (
	"testing"
)

func TestSortedSetImpl(t *testing.T) {
	s := newSortedSet()
	equals(t, 0, s.card())
	s.set(3.1415, "pi")
	s.set(2*3.1415, "2pi")
	s.set(3*3.1415, "3pi")
	equals(t, 3, s.card())
	// replace works?
	s.set(3.141592, "pi")
	equals(t, 3, s.card())

	// Get a key
	{
		pi, ok := s.get("pi")
		assert(t, ok, "got pi")
		equals(t, 3.141592, pi)
	}

	// Set ordered by score
	{
		elems := s.byScore(asc)
		equals(t, 3, len(elems))
		equals(t, ssElems{
			{3.141592, "pi"},
			{2 * 3.1415, "2pi"},
			{3 * 3.1415, "3pi"},
		}, elems)
	}

	// Rank of a key
	{
		rank, found := s.rankByScore("pi", asc)
		assert(t, found, "Found pi")
		equals(t, 0, rank)

		rank, found = s.rankByScore("3pi", desc)
		assert(t, found, "Found 3pi")
		equals(t, 0, rank)

		rank, found = s.rankByScore("3pi", asc)
		assert(t, found, "Found 3pi")
		equals(t, 2, rank)

		_, found = s.rankByScore("nosuch", asc)
		assert(t, !found, "Did not find nosuch")
	}
}

func TestSortOrder(t *testing.T) {
	// Keys with the same key should be sorted lexicographically
	s := newSortedSet()
	equals(t, 0, s.card())
	s.set(1, "one")
	s.set(1, "1")
	s.set(1, "eins")
	s.set(2, "two")
	s.set(2, "2")
	s.set(2, "zwei")
	s.set(3, "three")
	s.set(3, "3")
	s.set(3, "drei")
	equals(t, 9, s.card())

	// Set ordered by score, member
	{
		elems := s.byScore(asc)
		equals(t, 9, len(elems))
		equals(t, ssElems{
			{1, "1"},
			{1, "eins"},
			{1, "one"},
			{2, "2"},
			{2, "two"},
			{2, "zwei"},
			{3, "3"},
			{3, "drei"},
			{3, "three"},
		}, elems)
	}
}

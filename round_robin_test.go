package main

import "testing"

func TestRoundRobin(t *testing.T) {
	rr := RoundRobin{}
	rr.SetMax(2)

	for _, want := range []int{0, 1, 2, 0} {
		if got := rr.GetPos(); got != want {
			t.Errorf("RR Pos wrong: want %d got %d", want, got)
		}
	}
}

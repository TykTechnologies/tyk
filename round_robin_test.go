package main

import "testing"

func TestRR(t *testing.T) {
	thisArr1 := []string{"1", "2", "3"}

	thisRR := RoundRobin{}
	thisRR.SetMax(&thisArr1)

	val := thisRR.GetPos()

	if val != 0 {
		t.Error("RR Pos wrong, expected: 0 but got: ", val)
	}

	val = thisRR.GetPos()

	if val != 1 {
		t.Error("RR Pos wrong, expected: 1 but got: ", val)
	}

	val = thisRR.GetPos()

	if val != 2 {
		t.Error("RR Pos wrong, expected: 2 but got: ", val)
	}

	val = thisRR.GetPos()

	if val != 0 {
		t.Error("RR Pos wrong, expected: 0 but got: ", val)
	}
}

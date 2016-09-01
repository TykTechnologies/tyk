package main

import "testing"
import "github.com/TykTechnologies/tykcommon"

func TestRR(t *testing.T) {
	thisArr1 := []string{"1", "2", "3"}

	thisRR := RoundRobin{}
	asHL := tykcommon.NewHostListFromList(thisArr1)
	thisRR.SetMax(asHL)

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

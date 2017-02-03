package main

import "testing"
import "github.com/TykTechnologies/tyk/apidef"

func TestRR(t *testing.T) {
	arr1 := []string{"1", "2", "3"}

	rr := RoundRobin{}
	asHL := apidef.NewHostListFromList(arr1)
	rr.SetMax(asHL)

	val := rr.GetPos()
	if val != 0 {
		t.Error("RR Pos wrong, expected: 0 but got: ", val)
	}

	val = rr.GetPos()
	if val != 1 {
		t.Error("RR Pos wrong, expected: 1 but got: ", val)
	}

	val = rr.GetPos()
	if val != 2 {
		t.Error("RR Pos wrong, expected: 2 but got: ", val)
	}

	val = rr.GetPos()
	if val != 0 {
		t.Error("RR Pos wrong, expected: 0 but got: ", val)
	}
}

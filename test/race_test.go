package test

import "testing"

func TestIsRaceEnabled(t *testing.T) {
	if enabled := IsRaceEnabled(); enabled {
		t.Log("Flag -race passed")
	} else {
		t.Log("Flag -race omitted")
	}
}

package main

import (
	"github.com/TykTechnologies/tyk/storage"
	"testing"
)

func TestDefaultKeyGenerator_GenerateAuthKey(t *testing.T) {
	gen := DefaultKeyGenerator{}
	k := gen.GenerateAuthKey("55d5927329415b000100003")

	if !storage.InRange(k) {
		t.Fatal("Key should have range suffix!")
	}
}

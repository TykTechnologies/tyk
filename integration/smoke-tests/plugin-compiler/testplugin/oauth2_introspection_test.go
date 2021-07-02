package main

import "testing"

func TestA(t *testing.T) {
	t.Log("foo")
	t.FailNow()
}

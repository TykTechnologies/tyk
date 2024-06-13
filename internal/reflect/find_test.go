package reflect

import (
	"reflect"
	"testing"
)

func TestTraverseAndFind(t *testing.T) {
	type Address struct {
		Street string
		City   string
	}

	type Person struct {
		Name    string
		Address Address
		Phones  []string
	}
	p := Person{
		Name: "John",
		Address: Address{
			Street: "123 Main St",
			City:   "City",
		},
		Phones: []string{"123-456-7890", "456-789-0123"},
	}

	findFunc := func(s string) bool {
		return len(s) > 10
	}

	foundStrings := TraverseAndFind(&p, findFunc)

	expected := []string{"123 Main St", "123-456-7890", "456-789-0123"}

	if !reflect.DeepEqual(foundStrings, expected) {
		t.Errorf("TraverseAndFind did not find strings correctly. Expected: %v, Got: %v", expected, foundStrings)
	}
}

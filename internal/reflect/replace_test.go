package reflect

import (
	"reflect"
	"testing"
)

func TestTraverseAndReplace(t *testing.T) {
	type address struct {
		Street string
		City   string
	}

	type Person struct {
		Name    string
		address address
		Phones  []string
	}

	p := Person{
		Name: "John",
		address: address{
			Street: "123 Main St",
			City:   "John",
		},
		Phones: []string{"123-456-7890", "John"},
	}

	replaceFunc := func(s string) (string, bool) {
		if s == "John" {
			return "James", true
		}
		return s, false
	}

	TraverseAndReplace(&p, replaceFunc)

	expected := Person{
		Name: "James",
		address: address{
			Street: "123 Main St",
			City:   "John",
		},
		Phones: []string{"123-456-7890", "James"},
	}

	if !reflect.DeepEqual(p, expected) {
		t.Errorf("TraverseAndReplace did not replace values correctly. Expected: %v, Got: %v", expected, p)
	}
}

package reflect

import (
	clone "github.com/huandu/go-clone/generic"
)

// SW-REQ-065
// Clone is a hacky way to wrap the generic declaration.
// Using `var Clone = clone.Clone` is not allowed.
func Clone[T any](t T) T {
	return clone.Clone[T](t)
}

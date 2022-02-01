package jsonschema

// JSONPather makes validators traversible by JSON-pointers,
// which is required to support references in JSON schemas.
type JSONPather interface {
	// JSONProp take a string references for a given JSON property
	// implementations must return any matching property of that name
	// or nil if no such subproperty exists.
	// Note this also applies to array values, which are expected to interpret
	// valid numbers as an array index
	JSONProp(name string) interface{}
}

// JSONContainer is an interface that enables tree traversal by listing
// the immideate children of an object
type JSONContainer interface {
	// JSONChildren should return all immidiate children of this element
	JSONChildren() map[string]JSONPather
}

func walkJSON(elem JSONPather, fn func(elem JSONPather) error) error {
	if err := fn(elem); err != nil {
		return err
	}

	if con, ok := elem.(JSONContainer); ok {
		for _, ch := range con.JSONChildren() {
			if err := walkJSON(ch, fn); err != nil {
				return err
			}
		}
	}

	return nil
}

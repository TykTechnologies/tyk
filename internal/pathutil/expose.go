package pathutil

// ParsePath responsible for parsing single
func ParsePath(in string) (*Path, error) {
	return NewParser().Parse(in)
}

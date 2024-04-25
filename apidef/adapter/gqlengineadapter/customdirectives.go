package gqlengineadapter

import "strings"

type ToUpperDirective struct{}

func (t *ToUpperDirective) Name() string {
	return "toUpper"
}

func (t *ToUpperDirective) DataType() string {
	return "string"
}

func (t *ToUpperDirective) Execute(input []byte) ([]byte, error) {
	return []byte(strings.ToUpper(string(input))), nil
}

func NewToUpperDirective() *ToUpperDirective {
	return &ToUpperDirective{}
}

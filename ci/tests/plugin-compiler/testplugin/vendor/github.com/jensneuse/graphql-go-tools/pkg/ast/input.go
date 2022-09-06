package ast

import (
	"bytes"

	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

// Input is a raw graphql document containing the raw input + meta data
type Input struct {
	// RawBytes is the raw byte input
	RawBytes []byte
	// Length of RawBytes
	Length int
	// InputPosition is the current position in the RawBytes
	InputPosition int
	// TextPosition is the current position within the text (line and character information about the current Tokens)
	TextPosition position.Position
	// Variables are the json encoded variables of the operation
	Variables []byte
}

// Reset empties the Input
func (i *Input) Reset() {
	i.RawBytes = i.RawBytes[:0]
	i.Variables = i.Variables[:0]
	i.InputPosition = 0
	i.TextPosition.Reset()
}

// ResetInputBytes empties the input and sets it to bytes argument
func (i *Input) ResetInputBytes(bytes []byte) {
	i.Reset()
	i.AppendInputBytes(bytes)
	i.Length = len(i.RawBytes)
}

// ResetInputString empties the input and sets it to input string.
func (i *Input) ResetInputString(input string) {
	i.ResetInputBytes([]byte(input))
}

// AppendInputBytes appends a byte slice to the current input and returns the ByteSliceReference
func (i *Input) AppendInputBytes(bytes []byte) (ref ByteSliceReference) {
	ref.Start = uint32(len(i.RawBytes))
	i.RawBytes = append(i.RawBytes, bytes...)
	i.Length = len(i.RawBytes)
	ref.End = uint32(len(i.RawBytes))
	return
}

// AppendInputString appends a string to the current input and returns the ByteSliceReference
func (i *Input) AppendInputString(input string) ByteSliceReference {
	return i.AppendInputBytes([]byte(input))
}

// ByteSlice returns the byte slice for a given byte ByteSliceReference
func (i *Input) ByteSlice(reference ByteSliceReference) ByteSlice {
	return i.RawBytes[reference.Start:reference.End]
}

// ByteSliceString returns a string for a given ByteSliceReference
func (i *Input) ByteSliceString(reference ByteSliceReference) string {
	return unsafebytes.BytesToString(i.ByteSlice(reference))
}

// ByteSliceReferenceContentEquals compares the content of two byte slices and returns true if they are the same
func (i *Input) ByteSliceReferenceContentEquals(left, right ByteSliceReference) bool {
	if left.Length() != right.Length() {
		return false
	}
	length := int(left.Length())
	for k := 0; k < length; k++ {
		if i.RawBytes[int(left.Start)+k] != i.RawBytes[int(right.Start)+k] {
			return false
		}
	}
	return true
}

// ByteSlice is an alias for []byte
type ByteSlice []byte

// Equals compares a ByteSlice to another
func (b ByteSlice) Equals(another ByteSlice) bool {
	if len(b) != len(another) {
		return false
	}
	return bytes.Equal(b, another)
}

func (b ByteSlice) String() string {
	return unsafebytes.BytesToString(b)
}

func (b ByteSlice) MarshalJSON() ([]byte, error) {
	return append(append(literal.QUOTE, b...), literal.QUOTE...), nil
}

type ByteSlices []ByteSlice

func (b ByteSlices) String() string {
	out := "["
	for i := range b {
		if i != 0 {
			out += ","
		}
		out += string(b[i])
	}
	out += "]"
	return out
}

type ByteSliceReference struct {
	Start uint32
	End   uint32
}

func (b ByteSliceReference) Length() uint32 {
	return b.End - b.Start
}

// ByteSliceEquals compares two ByteSliceReferences from different Inputs
func ByteSliceEquals(left ByteSliceReference, leftInput Input, right ByteSliceReference, rightInput Input) bool {
	if left.Length() != right.Length() {
		return false
	}
	length := int(left.Length())
	for i := 0; i < length; i++ {
		if leftInput.RawBytes[int(left.Start)+i] != rightInput.RawBytes[int(right.Start)+i] {
			return false
		}
	}
	return true
}

type ByteSliceReferences []ByteSliceReference

func (b ByteSliceReferences) String(input *Input) string {
	out := "["
	for i := range b {
		if i != 0 {
			out += ","
		}
		if b[i].Length() == 0 {
			out += "query"
		} else {
			out += input.ByteSliceString(b[i])
		}
	}
	out += "]"
	return out
}

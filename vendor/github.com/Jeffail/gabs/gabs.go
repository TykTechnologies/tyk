/*
Copyright (c) 2014 Ashley Jeffs

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

// Package gabs implements a simplified wrapper around creating and parsing
// unknown or dynamic JSON.
package gabs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strconv"
	"strings"
)

//------------------------------------------------------------------------------

var (
	// ErrOutOfBounds indicates an index was out of bounds.
	ErrOutOfBounds = errors.New("out of bounds")

	// ErrNotObjOrArray is returned when a target is not an object or array type
	// but needs to be for the intended operation.
	ErrNotObjOrArray = errors.New("not an object or array")

	// ErrNotObj is returned when a target is not an object but needs to be for
	// the intended operation.
	ErrNotObj = errors.New("not an object")

	// ErrNotArray is returned when a target is not an array but needs to be for
	// the intended operation.
	ErrNotArray = errors.New("not an array")

	// ErrPathCollision is returned when creating a path failed because an
	// element collided with an existing value.
	ErrPathCollision = errors.New("encountered value collision whilst building path")

	// ErrInvalidInputObj is returned when the input value was not a
	// map[string]interface{}.
	ErrInvalidInputObj = errors.New("invalid input object")

	// ErrInvalidInputText is returned when the input data could not be parsed.
	ErrInvalidInputText = errors.New("input text could not be parsed")

	// ErrInvalidPath is returned when the filepath was not valid.
	ErrInvalidPath = errors.New("invalid file path")

	// ErrInvalidBuffer is returned when the input buffer contained an invalid
	// JSON string.
	ErrInvalidBuffer = errors.New("input buffer contained invalid JSON")
)

//------------------------------------------------------------------------------

func resolveJSONPointerHierarchy(path string) ([]string, error) {
	if len(path) < 1 {
		return nil, errors.New("failed to resolve JSON pointer: path must not be empty")
	}
	if path[0] != '/' {
		return nil, errors.New("failed to resolve JSON pointer: path must begin with '/'")
	}
	hierarchy := strings.Split(path, "/")[1:]
	for i, v := range hierarchy {
		v = strings.Replace(v, "~1", "/", -1)
		v = strings.Replace(v, "~0", "~", -1)
		hierarchy[i] = v
	}
	return hierarchy, nil
}

//------------------------------------------------------------------------------

// Container references a specific element within a JSON structure.
type Container struct {
	object interface{}
}

// Data returns the underlying interface{} of the target element in the JSON
// structure.
func (g *Container) Data() interface{} {
	if g == nil {
		return nil
	}
	return g.object
}

//------------------------------------------------------------------------------

// Path searches the JSON structure following a path in dot notation.
func (g *Container) Path(path string) *Container {
	return g.Search(strings.Split(path, ".")...)
}

// Search attempts to find and return an object within the JSON structure by
// following a provided hierarchy of field names to locate the target. If the
// search encounters an array and has not reached the end target then it will
// iterate each object of the array for the target and return all of the results
// in a JSON array.
func (g *Container) Search(hierarchy ...string) *Container {
	var object interface{}

	object = g.Data()
	for target := 0; target < len(hierarchy); target++ {
		if mmap, ok := object.(map[string]interface{}); ok {
			object, ok = mmap[hierarchy[target]]
			if !ok {
				return nil
			}
		} else if marray, ok := object.([]interface{}); ok {
			tmpArray := []interface{}{}
			for _, val := range marray {
				tmpGabs := &Container{val}
				res := tmpGabs.Search(hierarchy[target:]...)
				if res != nil {
					tmpArray = append(tmpArray, res.Data())
				}
			}
			if len(tmpArray) == 0 {
				return nil
			}
			return &Container{tmpArray}
		} else {
			return nil
		}
	}
	return &Container{object}
}

// JSONPointer parses a JSON pointer path (https://tools.ietf.org/html/rfc6901)
// and either returns a *gabs.Container containing the result or an error if the
// referenced item could not be found.
func (g *Container) JSONPointer(path string) (*Container, error) {
	hierarchy, err := resolveJSONPointerHierarchy(path)
	if err != nil {
		return nil, err
	}

	object := g.Data()
	for target := 0; target < len(hierarchy); target++ {
		pathSeg := hierarchy[target]
		if mmap, ok := object.(map[string]interface{}); ok {
			object, ok = mmap[pathSeg]
			if !ok {
				return nil, fmt.Errorf("failed to resolve JSON pointer: index '%v' value '%v' was not found", target, pathSeg)
			}
		} else if marray, ok := object.([]interface{}); ok {
			index, err := strconv.Atoi(pathSeg)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve JSON pointer: could not parse index '%v' value '%v' into array index: %v", target, pathSeg, err)
			}
			if len(marray) <= index {
				return nil, fmt.Errorf("failed to resolve JSON pointer: index '%v' value '%v' exceeded target array size of '%v'", target, pathSeg, len(marray))
			}
			object = marray[index]
		} else {
			return &Container{nil}, fmt.Errorf("failed to resolve JSON pointer: index '%v' field '%v' was not found", target, pathSeg)
		}
	}
	return &Container{object}, nil
}

// S is a shorthand alias for Search.
func (g *Container) S(hierarchy ...string) *Container {
	return g.Search(hierarchy...)
}

// Exists checks whether a path exists.
func (g *Container) Exists(hierarchy ...string) bool {
	return g.Search(hierarchy...) != nil
}

// ExistsP checks whether a dot notation path exists.
func (g *Container) ExistsP(path string) bool {
	return g.Exists(strings.Split(path, ".")...)
}

// Index attempts to find and return an element within a JSON array by an index.
func (g *Container) Index(index int) *Container {
	if array, ok := g.Data().([]interface{}); ok {
		if index >= len(array) {
			return &Container{nil}
		}
		return &Container{array[index]}
	}
	return &Container{nil}
}

// Children returns a slice of all children of an array element. This also works
// for objects, however, the children returned for an object will be in a random
// order and you lose the names of the returned objects this way.
func (g *Container) Children() ([]*Container, error) {
	if array, ok := g.Data().([]interface{}); ok {
		children := make([]*Container, len(array))
		for i := 0; i < len(array); i++ {
			children[i] = &Container{array[i]}
		}
		return children, nil
	}
	if mmap, ok := g.Data().(map[string]interface{}); ok {
		children := []*Container{}
		for _, obj := range mmap {
			children = append(children, &Container{obj})
		}
		return children, nil
	}
	return nil, ErrNotObjOrArray
}

// ChildrenMap returns a map of all the children of an object element.
func (g *Container) ChildrenMap() (map[string]*Container, error) {
	if mmap, ok := g.Data().(map[string]interface{}); ok {
		children := map[string]*Container{}
		for name, obj := range mmap {
			children[name] = &Container{obj}
		}
		return children, nil
	}
	return nil, ErrNotObj
}

//------------------------------------------------------------------------------

// Set the value of a field at a JSON path, any parts of the path that do not
// exist will be constructed, and if a collision occurs with a non object type
// whilst iterating the path an error is returned.
func (g *Container) Set(value interface{}, path ...string) (*Container, error) {
	if len(path) == 0 {
		g.object = value
		return g, nil
	}
	var object interface{}
	if g.object == nil {
		g.object = map[string]interface{}{}
	}
	object = g.object
	for target := 0; target < len(path); target++ {
		if mmap, ok := object.(map[string]interface{}); ok {
			if target == len(path)-1 {
				mmap[path[target]] = value
			} else if mmap[path[target]] == nil {
				mmap[path[target]] = map[string]interface{}{}
			}
			object = mmap[path[target]]
		} else {
			return &Container{nil}, ErrPathCollision
		}
	}
	return &Container{object}, nil
}

// SetP sets the value of a field at a JSON path using dot notation, any parts
// of the path that do not exist will be constructed, and if a collision occurs
// with a non object type whilst iterating the path an error is returned.
func (g *Container) SetP(value interface{}, path string) (*Container, error) {
	return g.Set(value, strings.Split(path, ".")...)
}

// SetIndex attempts to set a value of an array element based on an index.
func (g *Container) SetIndex(value interface{}, index int) (*Container, error) {
	if array, ok := g.Data().([]interface{}); ok {
		if index >= len(array) {
			return &Container{nil}, ErrOutOfBounds
		}
		array[index] = value
		return &Container{array[index]}, nil
	}
	return &Container{nil}, ErrNotArray
}

// SetJSONPointer parses a JSON pointer path
// (https://tools.ietf.org/html/rfc6901) and sets the leaf to a value. Returns
// an error if the pointer could not be resolved due to missing fields.
func (g *Container) SetJSONPointer(value interface{}, path string) error {
	hierarchy, err := resolveJSONPointerHierarchy(path)
	if err != nil {
		return err
	}

	if len(hierarchy) == 0 {
		g.object = value
		return nil
	}

	object := g.object

	for target := 0; target < len(hierarchy); target++ {
		pathSeg := hierarchy[target]
		if mmap, ok := object.(map[string]interface{}); ok {
			if target == len(hierarchy)-1 {
				object = value
				mmap[pathSeg] = object
			} else if object = mmap[pathSeg]; object == nil {
				return fmt.Errorf("failed to resolve JSON pointer: index '%v' value '%v' was not found", target, pathSeg)
			}
		} else if marray, ok := object.([]interface{}); ok {
			index, err := strconv.Atoi(pathSeg)
			if err != nil {
				return fmt.Errorf("failed to resolve JSON pointer: could not parse index '%v' value '%v' into array index: %v", target, pathSeg, err)
			}
			if len(marray) <= index {
				return fmt.Errorf("failed to resolve JSON pointer: index '%v' value '%v' exceeded target array size of '%v'", target, pathSeg, len(marray))
			}
			if target == len(hierarchy)-1 {
				object = value
				marray[index] = object
			} else if object = marray[index]; object == nil {
				return fmt.Errorf("failed to resolve JSON pointer: index '%v' value '%v' was not found", target, pathSeg)
			}
		} else {
			return fmt.Errorf("failed to resolve JSON pointer: index '%v' value '%v' was not found", target, pathSeg)
		}
	}
	return nil
}

// Object creates a new JSON object at a target path. Returns an error if the
// path contains a collision with a non object type.
func (g *Container) Object(path ...string) (*Container, error) {
	return g.Set(map[string]interface{}{}, path...)
}

// ObjectP creates a new JSON object at a target path using dot notation.
// Returns an error if the path contains a collision with a non object type.
func (g *Container) ObjectP(path string) (*Container, error) {
	return g.Object(strings.Split(path, ".")...)
}

// ObjectI creates a new JSON object at an array index. Returns an error if the
// object is not an array or the index is out of bounds.
func (g *Container) ObjectI(index int) (*Container, error) {
	return g.SetIndex(map[string]interface{}{}, index)
}

// Array creates a new JSON array at a path. Returns an error if the path
// contains a collision with a non object type.
func (g *Container) Array(path ...string) (*Container, error) {
	return g.Set([]interface{}{}, path...)
}

// ArrayP creates a new JSON array at a path using dot notation. Returns an
// error if the path contains a collision with a non object type.
func (g *Container) ArrayP(path string) (*Container, error) {
	return g.Array(strings.Split(path, ".")...)
}

// ArrayI creates a new JSON array within an array at an index. Returns an error
// if the element is not an array or the index is out of bounds.
func (g *Container) ArrayI(index int) (*Container, error) {
	return g.SetIndex([]interface{}{}, index)
}

// ArrayOfSize creates a new JSON array of a particular size at a path. Returns
// an error if the path contains a collision with a non object type.
func (g *Container) ArrayOfSize(size int, path ...string) (*Container, error) {
	a := make([]interface{}, size)
	return g.Set(a, path...)
}

// ArrayOfSizeP creates a new JSON array of a particular size at a path using
// dot notation. Returns an error if the path contains a collision with a non
// object type.
func (g *Container) ArrayOfSizeP(size int, path string) (*Container, error) {
	return g.ArrayOfSize(size, strings.Split(path, ".")...)
}

// ArrayOfSizeI create a new JSON array of a particular size within an array at
// an index. Returns an error if the element is not an array or the index is out
// of bounds.
func (g *Container) ArrayOfSizeI(size, index int) (*Container, error) {
	a := make([]interface{}, size)
	return g.SetIndex(a, index)
}

// Delete an element at a path, an error is returned if the element does not
// exist.
func (g *Container) Delete(path ...string) error {
	var object interface{}

	if g.object == nil {
		return ErrNotObj
	}
	object = g.object
	for target := 0; target < len(path); target++ {
		if mmap, ok := object.(map[string]interface{}); ok {
			if target == len(path)-1 {
				if _, ok := mmap[path[target]]; ok {
					delete(mmap, path[target])
				} else {
					return ErrNotObj
				}
			}
			object = mmap[path[target]]
		} else {
			return ErrNotObj
		}
	}
	return nil
}

// DeleteP deletes an element at a path using dot notation, an error is returned
// if the element does not exist.
func (g *Container) DeleteP(path string) error {
	return g.Delete(strings.Split(path, ".")...)
}

// MergeFn merges two objects using a provided function to resolve collisions.
//
// The collision function receives two interface{} arguments, destination (the
// original object) and source (the object being merged into the destination).
// Which ever value is returned becomes the new value in the destination object
// at the location of the collision.
func (g *Container) MergeFn(source *Container, collisionFn func(destination, source interface{}) interface{}) error {
	var recursiveFnc func(map[string]interface{}, []string) error
	recursiveFnc = func(mmap map[string]interface{}, path []string) error {
		for key, value := range mmap {
			newPath := append(path, key)
			if g.Exists(newPath...) {
				existingData := g.Search(newPath...).Data()
				switch t := value.(type) {
				case map[string]interface{}:
					switch existingVal := existingData.(type) {
					case map[string]interface{}:
						if err := recursiveFnc(t, newPath); err != nil {
							return err
						}
					default:
						if _, err := g.Set(collisionFn(existingVal, t), newPath...); err != nil {
							return err
						}
					}
				default:
					if _, err := g.Set(collisionFn(existingData, t), newPath...); err != nil {
						return err
					}
				}
			} else {
				// path doesn't exist. So set the value
				if _, err := g.Set(value, newPath...); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if mmap, ok := source.Data().(map[string]interface{}); ok {
		return recursiveFnc(mmap, []string{})
	}
	return nil
}

// Merge a source object into an existing destination object. When a collision
// is found within the merged structures (both a source and destination object
// contain the same non-object keys) the result will be an array containing both
// values, where values that are already arrays will be expanded into the
// resulting array.
//
// It is possible to merge structures will different collision behaviours with
// MergeFn.
func (g *Container) Merge(source *Container) error {
	return g.MergeFn(source, func(dest, source interface{}) interface{} {
		destArr, destIsArray := dest.([]interface{})
		sourceArr, sourceIsArray := source.([]interface{})
		if destIsArray {
			if sourceIsArray {
				return append(destArr, sourceArr...)
			}
			return append(destArr, source)
		}
		if sourceIsArray {
			return append(append([]interface{}{}, dest), sourceArr...)
		}
		return []interface{}{dest, source}
	})
}

//------------------------------------------------------------------------------

/*
Array modification/search - Keeping these options simple right now, no need for
anything more complicated since you can just cast to []interface{}, modify and
then reassign with Set.
*/

// ArrayAppend attempts to append a value onto a JSON array at a path. If the
// target is not a JSON array then it will be converted into one, with its
// original contents set to the first element of the array.
func (g *Container) ArrayAppend(value interface{}, path ...string) error {
	if array, ok := g.Search(path...).Data().([]interface{}); ok {
		array = append(array, value)
		_, err := g.Set(array, path...)
		return err
	}

	newArray := []interface{}{}
	if d := g.Search(path...).Data(); d != nil {
		newArray = append(newArray, d)
	}
	newArray = append(newArray, value)

	_, err := g.Set(newArray, path...)
	return err
}

// ArrayAppendP attempts to append a value onto a JSON array at a path using dot
// notation. If the target is not a JSON array then it will be converted into
// one, with its original contents set to the first element of the array.
func (g *Container) ArrayAppendP(value interface{}, path string) error {
	return g.ArrayAppend(value, strings.Split(path, ".")...)
}

// ArrayRemove attempts to remove an element identified by an index from a JSON
// array at a path.
func (g *Container) ArrayRemove(index int, path ...string) error {
	if index < 0 {
		return ErrOutOfBounds
	}
	array, ok := g.Search(path...).Data().([]interface{})
	if !ok {
		return ErrNotArray
	}
	if index < len(array) {
		array = append(array[:index], array[index+1:]...)
	} else {
		return ErrOutOfBounds
	}
	_, err := g.Set(array, path...)
	return err
}

// ArrayRemoveP attempts to remove an element identified by an index from a JSON
// array at a path using dot notation.
func (g *Container) ArrayRemoveP(index int, path string) error {
	return g.ArrayRemove(index, strings.Split(path, ".")...)
}

// ArrayElement attempts to access an element by an index from a JSON array at a
// path.
func (g *Container) ArrayElement(index int, path ...string) (*Container, error) {
	if index < 0 {
		return &Container{nil}, ErrOutOfBounds
	}
	array, ok := g.Search(path...).Data().([]interface{})
	if !ok {
		return &Container{nil}, ErrNotArray
	}
	if index < len(array) {
		return &Container{array[index]}, nil
	}
	return &Container{nil}, ErrOutOfBounds
}

// ArrayElementP attempts to access an element by an index from a JSON array at
// a path using dot notation.
func (g *Container) ArrayElementP(index int, path string) (*Container, error) {
	return g.ArrayElement(index, strings.Split(path, ".")...)
}

// ArrayCount counts the number of elements in a JSON array at a path.
func (g *Container) ArrayCount(path ...string) (int, error) {
	if array, ok := g.Search(path...).Data().([]interface{}); ok {
		return len(array), nil
	}
	return 0, ErrNotArray
}

// ArrayCountP counts the number of elements in a JSON array at a path using dot
// notation.
func (g *Container) ArrayCountP(path string) (int, error) {
	return g.ArrayCount(strings.Split(path, ".")...)
}

//------------------------------------------------------------------------------

// Bytes marshals an element to a JSON []byte blob.
func (g *Container) Bytes() []byte {
	if g.Data() != nil {
		if bytes, err := json.Marshal(g.object); err == nil {
			return bytes
		}
	}
	return []byte("{}")
}

// BytesIndent marshals an element to a JSON []byte blob formatted with a prefix
// and indent string.
func (g *Container) BytesIndent(prefix string, indent string) []byte {
	if g.object != nil {
		if bytes, err := json.MarshalIndent(g.object, prefix, indent); err == nil {
			return bytes
		}
	}
	return []byte("{}")
}

// String marshals an element to a JSON formatted string.
func (g *Container) String() string {
	return string(g.Bytes())
}

// StringIndent marshals an element to a JSON string formatted with a prefix and
// indent string.
func (g *Container) StringIndent(prefix string, indent string) string {
	return string(g.BytesIndent(prefix, indent))
}

// EncodeOpt is a functional option for the EncodeJSON method.
type EncodeOpt func(e *json.Encoder)

// EncodeOptHTMLEscape sets the encoder to escape the JSON for html.
func EncodeOptHTMLEscape(doEscape bool) EncodeOpt {
	return func(e *json.Encoder) {
		e.SetEscapeHTML(doEscape)
	}
}

// EncodeOptIndent sets the encoder to indent the JSON output.
func EncodeOptIndent(prefix string, indent string) EncodeOpt {
	return func(e *json.Encoder) {
		e.SetIndent(prefix, indent)
	}
}

// EncodeJSON marshals an element to a JSON formatted []byte using a variant
// list of modifier functions for the encoder being used. Functions for
// modifying the output are prefixed with EncodeOpt, e.g. EncodeOptHTMLEscape.
func (g *Container) EncodeJSON(encodeOpts ...EncodeOpt) []byte {
	var b bytes.Buffer
	encoder := json.NewEncoder(&b)
	encoder.SetEscapeHTML(false) // Do not escape by default.
	for _, opt := range encodeOpts {
		opt(encoder)
	}
	if err := encoder.Encode(g.object); err != nil {
		return []byte("{}")
	}
	result := b.Bytes()
	if len(result) > 0 {
		result = result[:len(result)-1]
	}
	return result
}

// New creates a new gabs JSON object.
func New() *Container {
	return &Container{map[string]interface{}{}}
}

// Consume an already unmarshalled JSON object (or a new map[string]interface{})
// into a *Container.
func Consume(root interface{}) (*Container, error) {
	return &Container{root}, nil
}

// ParseJSON unmarshals a JSON byte slice into a *Container.
func ParseJSON(sample []byte) (*Container, error) {
	var gabs Container

	if err := json.Unmarshal(sample, &gabs.object); err != nil {
		return nil, err
	}

	return &gabs, nil
}

// ParseJSONDecoder applies a json.Decoder to a *Container.
func ParseJSONDecoder(decoder *json.Decoder) (*Container, error) {
	var gabs Container

	if err := decoder.Decode(&gabs.object); err != nil {
		return nil, err
	}

	return &gabs, nil
}

// ParseJSONFile reads a file and unmarshals the contents into a *Container.
func ParseJSONFile(path string) (*Container, error) {
	if len(path) > 0 {
		cBytes, err := ioutil.ReadFile(path)
		if err != nil {
			return nil, err
		}

		container, err := ParseJSON(cBytes)
		if err != nil {
			return nil, err
		}

		return container, nil
	}
	return nil, ErrInvalidPath
}

// ParseJSONBuffer reads a buffer and unmarshals the contents into a *Container.
func ParseJSONBuffer(buffer io.Reader) (*Container, error) {
	var gabs Container
	jsonDecoder := json.NewDecoder(buffer)
	if err := jsonDecoder.Decode(&gabs.object); err != nil {
		return nil, err
	}

	return &gabs, nil
}

//------------------------------------------------------------------------------

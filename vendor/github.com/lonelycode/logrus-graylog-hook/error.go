package graylog

import "encoding/json"

// newMarshalableError builds an error which encodes its error message into JSON
func newMarshalableError(err error) *marshalableError {
	return &marshalableError{err}
}

// a marshalableError is an error that can be encoded into JSON
type marshalableError struct {
	err error
}

// MarshalJSON implements json.Marshaler for marshalableError
func (m *marshalableError) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.err.Error())
}

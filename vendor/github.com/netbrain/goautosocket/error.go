// Copyright © 2015 Clement 'cmc' Rey <cr.rey.clement@gmail.com>.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package gas

// ----------------------------------------------------------------------------

// Error is the error type of the GAS package.
//
// It implements the error interface.
type Error int

const (
	// ErrMaxRetries is returned when the called function failed after the
	// maximum number of allowed tries.
	ErrMaxRetries Error = 0x01
)

// ----------------------------------------------------------------------------

// Error returns the error as a string.
func (e Error) Error() string {
	switch e {
	case 0x01:
		return "ErrMaxRetries"
	default:
		return "unknown error"
	}
}

package uuid

import (
	uuid "github.com/satori/go.uuid"
)

// New returns a V4 UUID.
func New() string {
	return uuid.NewV4().String()
}

// Valid returns true if id is parsed as UUID without error.
func Valid(id string) bool {
	_, err := uuid.FromString(id)
	return err == nil
}

package uuid

import (
	"strings"

	"github.com/gofrs/uuid"
)

// New returns a V4 UUID.
func New() string {
	id, err := uuid.NewV4()
	checkErrAndPanic(err, "Error generating UUID")
	return id.String()
}

func checkErrAndPanic(err error, message string) {
	if err != nil {
		// This is unfortunate, but UUID generation is used for DB
		// record IDs and similar. If we can't generate an UUID, we
		// can't reasonably recover from that situation. We should
		// never reach this code.
		panic(message + " " + err.Error())
	}
}

// NewHex returns a V4 UUID without dashes.
func NewHex() string {
	return strings.ReplaceAll(New(), "-", "")
}

// Valid returns true if id is parsed as UUID without error.
func Valid(id string) bool {
	_, err := uuid.FromString(id)
	return err == nil
}

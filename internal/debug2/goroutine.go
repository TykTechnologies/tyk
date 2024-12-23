package debug2

import (
	"bytes"
	"fmt"
	"regexp"
	"runtime/pprof"
	"strings"
)

// Record captures goroutine states
type Record struct {
	buffer  *bytes.Buffer
	ignores []string
}

// NewRecord creates a new Record and populates it with the current goroutine dump.
func NewRecord() *Record {
	result := &Record{
		buffer: bytes.NewBuffer([]byte{}),
	}

	pprof.Lookup("goroutine").WriteTo(result.buffer, 1)

	result.SetIgnores([]string{
		"runtime/pprof.writeRuntimeProfile",
	})
	return result
}

func (r *Record) SetIgnores(ignores []string) {
	r.ignores = ignores
}

var headerMatchRe = regexp.MustCompile(`^[0-9]+ @ 0x.*`)

// parseGoroutines parses goroutines from the buffer into a map where each key is a
// goroutine header and the value is its stack trace as a slice of strings.
func (r *Record) parseGoroutines() map[string][]string {
	goroutines := make(map[string][]string)
	var currentHeader string
	var currentStack []string
	toDelete := []string{}
	lines := strings.Split(r.buffer.String(), "\n")

	for _, line := range lines {
		var skip bool
		for _, ign := range r.ignores {
			if strings.Contains(line, ign) {
				skip = true
				break
			}
		}

		if skip {
			toDelete = append(toDelete, currentHeader)
		}

		if headerMatchRe.MatchString(line) {
			// Save the previous goroutine and reset
			if currentHeader != "" {
				goroutines[currentHeader] = currentStack
			}
			currentHeader = line
			currentStack = []string{line}
		} else if currentHeader != "" {
			// Add stack trace lines to the current goroutine
			currentStack = append(currentStack, line)
		}
	}

	// Save the last goroutine
	if currentHeader != "" {
		goroutines[currentHeader] = currentStack
	}

	for _, key := range toDelete {
		delete(goroutines, key)
	}

	return goroutines
}

// Since compares the current Record with another Record and returns a new Record
// containing only the goroutines found in the current Record but not in the last.
func (r *Record) Since(last *Record) *Record {
	currentGoroutines := r.parseGoroutines()
	lastGoroutines := last.parseGoroutines()

	diffBuffer := bytes.NewBuffer([]byte{})
	for header, stack := range currentGoroutines {
		if _, exists := lastGoroutines[header]; !exists {
			diffBuffer.WriteString(header + "\n")
			for _, line := range stack {
				diffBuffer.WriteString(line + "\n")
			}
		}
	}

	return &Record{
		buffer: diffBuffer,
	}
}

// Count returns the number of unique goroutines in the Record.
func (r *Record) Count() int {
	return len(r.parseGoroutines())
}

// String implements the fmt.Stringer interface, providing a formatted view
// of the goroutines in the Record.
func (r *Record) String() string {
	goroutines := r.parseGoroutines()
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("Number of goroutines: %d\n", len(goroutines)))
	for header, stack := range goroutines {
		builder.WriteString("--- Goroutine ---\n")
		builder.WriteString(header + "\n")
		for _, line := range stack {
			builder.WriteString(line + "\n")
		}
	}
	return builder.String()
}

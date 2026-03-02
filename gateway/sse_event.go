package gateway

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
)

// SSEEvent represents a single Server-Sent Event as defined by the W3C
// EventSource specification (https://html.spec.whatwg.org/multipage/server-sent-events.html).
type SSEEvent struct {
	ID    string   // Last event ID.
	Event string   // Event type (default: "message").
	Data  []string // Data lines (joined with \n when serialized).
	Retry int      // Reconnection time in milliseconds (0 = not set).
}

// errIncompleteEvent is returned by parseSSEEvent when the buffer does not
// contain a complete event (no blank-line terminator found).
var errIncompleteEvent = errors.New("incomplete SSE event")

// findEventBoundary locates the first event boundary in buffer, which is a
// blank line (two consecutive line endings) per the SSE specification.
// It returns the byte index where the terminator starts and the length of the
// terminator sequence. If no boundary is found it returns (-1, 0).
//
// Supported terminators: \n\n, \r\n\r\n, \r\r, and mixed combinations such
// as \r\n\n or \n\r\n.
func findEventBoundary(buffer []byte) (int, int) {
	i := 0
	for i < len(buffer) {
		// Look for the start of a line ending.
		switch buffer[i] {
		case '\n':
			// \n\n
			if i+1 < len(buffer) && buffer[i+1] == '\n' {
				return i, 2
			}
			// \n\r\n
			if i+2 < len(buffer) && buffer[i+1] == '\r' && buffer[i+2] == '\n' {
				return i, 3
			}
		case '\r':
			if i+1 < len(buffer) {
				if buffer[i+1] == '\n' {
					// \r\n followed by \r\n
					if i+3 < len(buffer) && buffer[i+2] == '\r' && buffer[i+3] == '\n' {
						return i, 4
					}
					// \r\n followed by \n
					if i+2 < len(buffer) && buffer[i+2] == '\n' {
						return i, 3
					}
					// \r\n followed by \r (not \r\n) — mixed line endings
					if i+2 < len(buffer) && buffer[i+2] == '\r' {
						return i, 3
					}
				} else if buffer[i+1] == '\r' {
					// \r\r
					return i, 2
				}
			}
		}
		i++
	}
	return -1, 0
}

// splitSSELines splits data by any valid SSE line ending (\n, \r\n, or \r).
func splitSSELines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	i := 0
	for i < len(data) {
		switch data[i] {
		case '\n':
			lines = append(lines, data[start:i])
			start = i + 1
		case '\r':
			lines = append(lines, data[start:i])
			if i+1 < len(data) && data[i+1] == '\n' {
				i++ // skip the \n in \r\n
			}
			start = i + 1
		}
		i++
	}
	// Append remaining content (if any) as the last line.
	if start <= len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}

// parseSSEEvent attempts to parse a single complete SSE event from buffer.
//
// It returns:
//   - event: the parsed event (nil if the block was only comments/empty)
//   - rawBytes: the original bytes of this event block (including terminator)
//   - rest: remaining bytes after this event
//   - err: errIncompleteEvent if no complete event boundary was found
//
// Comment lines (starting with ':') are silently ignored per the spec.
func parseSSEEvent(buffer []byte) (event *SSEEvent, rawBytes []byte, rest []byte, err error) {
	idx, termLen := findEventBoundary(buffer)
	if idx < 0 {
		return nil, nil, buffer, errIncompleteEvent
	}

	block := buffer[:idx]
	rawBytes = buffer[:idx+termLen]
	rest = buffer[idx+termLen:]

	lines := splitSSELines(block)

	var ev SSEEvent
	hasFields := false

	for _, line := range lines {
		if len(line) == 0 {
			// Empty line within a block; should not happen before the
			// boundary, but skip gracefully.
			continue
		}

		// Comment lines start with ':'.
		if line[0] == ':' {
			continue
		}

		// Parse "field: value" or "field:value" or "field" (no colon).
		var field, value string
		colonIdx := bytes.IndexByte(line, ':')
		if colonIdx < 0 {
			// Field name only, value is empty string.
			field = string(line)
			value = ""
		} else {
			field = string(line[:colonIdx])
			val := line[colonIdx+1:]
			// Per spec: if value starts with a space, remove one leading space.
			if len(val) > 0 && val[0] == ' ' {
				val = val[1:]
			}
			value = string(val)
		}

		hasFields = true

		switch field {
		case "event":
			ev.Event = value
		case "data":
			ev.Data = append(ev.Data, value)
		case "id":
			// Per spec: if value contains U+0000, ignore the field.
			if !strings.Contains(value, "\x00") {
				ev.ID = value
			}
		case "retry":
			if n, parseErr := strconv.Atoi(value); parseErr == nil && n >= 0 {
				ev.Retry = n
			}
		default:
			// Unknown fields are ignored per the spec.
		}
	}

	if !hasFields {
		// Block contained only comments or empty lines; no event to emit.
		return nil, rawBytes, rest, nil
	}

	return &ev, rawBytes, rest, nil
}

// serializeSSEEvent converts an SSEEvent back to its wire format.
// The output always uses \n line endings and is terminated with \n\n.
func serializeSSEEvent(event *SSEEvent) []byte {
	var buf bytes.Buffer

	if event.Event != "" {
		buf.WriteString("event: ")
		buf.WriteString(event.Event)
		buf.WriteByte('\n')
	}

	for _, d := range event.Data {
		buf.WriteString("data: ")
		buf.WriteString(d)
		buf.WriteByte('\n')
	}

	if event.ID != "" {
		buf.WriteString("id: ")
		buf.WriteString(event.ID)
		buf.WriteByte('\n')
	}

	if event.Retry > 0 {
		buf.WriteString("retry: ")
		buf.WriteString(strconv.Itoa(event.Retry))
		buf.WriteByte('\n')
	}

	// Event terminator.
	buf.WriteByte('\n')

	return buf.Bytes()
}

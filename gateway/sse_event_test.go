package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindEventBoundary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantIdx int
		wantLen int
	}{
		{
			name:    "LF LF",
			input:   "data: hello\n\n",
			wantIdx: 11,
			wantLen: 2,
		},
		{
			name:    "CRLF CRLF",
			input:   "data: hello\r\n\r\n",
			wantIdx: 11,
			wantLen: 4,
		},
		{
			name:    "CR CR",
			input:   "data: hello\r\r",
			wantIdx: 11,
			wantLen: 2,
		},
		{
			name:    "CRLF LF mixed",
			input:   "data: hello\r\n\n",
			wantIdx: 11,
			wantLen: 3,
		},
		{
			name:    "LF CRLF mixed",
			input:   "data: hello\n\r\n",
			wantIdx: 11,
			wantLen: 3,
		},
		{
			name:    "CRLF CR mixed",
			input:   "data: hello\r\n\r",
			wantIdx: 11,
			wantLen: 3,
		},
		{
			name:    "no boundary",
			input:   "data: hello\n",
			wantIdx: -1,
			wantLen: 0,
		},
		{
			name:    "empty input",
			input:   "",
			wantIdx: -1,
			wantLen: 0,
		},
		{
			name:    "only boundary",
			input:   "\n\n",
			wantIdx: 0,
			wantLen: 2,
		},
		{
			name:    "multiple events pick first",
			input:   "data: a\n\ndata: b\n\n",
			wantIdx: 7,
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			idx, length := findEventBoundary([]byte(tt.input))
			assert.Equal(t, tt.wantIdx, idx, "index")
			assert.Equal(t, tt.wantLen, length, "length")
		})
	}
}

func TestSplitSSELines(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "LF",
			input: "a\nb\nc",
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "CRLF",
			input: "a\r\nb\r\nc",
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "CR",
			input: "a\rb\rc",
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "mixed",
			input: "a\nb\r\nc\rd",
			want:  []string{"a", "b", "c", "d"},
		},
		{
			name:  "trailing newline",
			input: "a\n",
			want:  []string{"a", ""},
		},
		{
			name:  "empty",
			input: "",
			want:  []string{""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := splitSSELines([]byte(tt.input))
			result := make([]string, len(got))
			for i, b := range got {
				result[i] = string(b)
			}
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestParseSSEEvent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantEvent *SSEEvent
		wantRest  string
		wantErr   error
	}{
		{
			name:  "all fields",
			input: "event: status\ndata: line1\ndata: line2\nid: 42\nretry: 3000\n\n",
			wantEvent: &SSEEvent{
				ID:    "42",
				Event: "status",
				Data:  []string{"line1", "line2"},
				Retry: 3000,
			},
			wantRest: "",
		},
		{
			name:  "data only",
			input: "data: hello world\n\n",
			wantEvent: &SSEEvent{
				Data: []string{"hello world"},
			},
			wantRest: "",
		},
		{
			name:    "incomplete event",
			input:   "data: hello",
			wantErr: errIncompleteEvent,
		},
		{
			name:      "comment only block",
			input:     ": this is a comment\n\n",
			wantEvent: nil,
			wantRest:  "",
		},
		{
			name:  "comment mixed with fields",
			input: ": keep-alive\ndata: payload\n\n",
			wantEvent: &SSEEvent{
				Data: []string{"payload"},
			},
			wantRest: "",
		},
		{
			name:  "field without colon",
			input: "data\n\n",
			wantEvent: &SSEEvent{
				Data: []string{""},
			},
			wantRest: "",
		},
		{
			name:  "field with colon no space",
			input: "data:nospace\n\n",
			wantEvent: &SSEEvent{
				Data: []string{"nospace"},
			},
			wantRest: "",
		},
		{
			name:  "event with CRLF line endings",
			input: "event: update\r\ndata: value\r\n\r\n",
			wantEvent: &SSEEvent{
				Event: "update",
				Data:  []string{"value"},
			},
			wantRest: "",
		},
		{
			name:  "event with CR line endings",
			input: "data: cr\r\r",
			wantEvent: &SSEEvent{
				Data: []string{"cr"},
			},
			wantRest: "",
		},
		{
			name:  "event with CRLF CR mixed boundary",
			input: "data: mixed\r\n\r",
			wantEvent: &SSEEvent{
				Data: []string{"mixed"},
			},
			wantRest: "",
		},
		{
			name:  "multiple events returns first",
			input: "data: first\n\ndata: second\n\n",
			wantEvent: &SSEEvent{
				Data: []string{"first"},
			},
			wantRest: "data: second\n\n",
		},
		{
			name:  "retry non-numeric ignored",
			input: "retry: abc\ndata: x\n\n",
			wantEvent: &SSEEvent{
				Data: []string{"x"},
			},
			wantRest: "",
		},
		{
			name:  "id with null character ignored",
			input: "id: a\x00b\ndata: x\n\n",
			wantEvent: &SSEEvent{
				Data: []string{"x"},
			},
			wantRest: "",
		},
		{
			name:  "unknown field ignored",
			input: "unknown: value\ndata: x\n\n",
			wantEvent: &SSEEvent{
				Data: []string{"x"},
			},
			wantRest: "",
		},
		{
			name:  "empty data line",
			input: "data: \n\n",
			wantEvent: &SSEEvent{
				Data: []string{""},
			},
			wantRest: "",
		},
		{
			name:  "data with leading space preserved beyond first",
			input: "data:  two spaces\n\n",
			wantEvent: &SSEEvent{
				Data: []string{" two spaces"},
			},
			wantRest: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			event, _, rest, err := parseSSEEvent([]byte(tt.input))
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			if tt.wantEvent == nil {
				assert.Nil(t, event)
			} else {
				require.NotNil(t, event)
				assert.Equal(t, tt.wantEvent.Event, event.Event, "Event")
				assert.Equal(t, tt.wantEvent.Data, event.Data, "Data")
				assert.Equal(t, tt.wantEvent.ID, event.ID, "ID")
				assert.Equal(t, tt.wantEvent.Retry, event.Retry, "Retry")
			}

			assert.Equal(t, tt.wantRest, string(rest), "rest")
		})
	}
}

func TestSerializeSSEEvent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		event SSEEvent
		want  string
	}{
		{
			name: "all fields",
			event: SSEEvent{
				Event: "update",
				Data:  []string{"line1", "line2"},
				ID:    "99",
				Retry: 5000,
			},
			want: "event: update\ndata: line1\ndata: line2\nid: 99\nretry: 5000\n\n",
		},
		{
			name: "data only",
			event: SSEEvent{
				Data: []string{"hello"},
			},
			want: "data: hello\n\n",
		},
		{
			name:  "empty event",
			event: SSEEvent{},
			want:  "\n",
		},
		{
			name: "event type only",
			event: SSEEvent{
				Event: "ping",
			},
			want: "event: ping\n\n",
		},
		{
			name: "multiline data",
			event: SSEEvent{
				Data: []string{"a", "b", "c"},
			},
			want: "data: a\ndata: b\ndata: c\n\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := serializeSSEEvent(&tt.event)
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestSerializeParseRoundTrip(t *testing.T) {
	t.Parallel()

	original := &SSEEvent{
		Event: "message",
		Data:  []string{"payload line 1", "payload line 2"},
		ID:    "abc-123",
		Retry: 1500,
	}

	serialized := serializeSSEEvent(original)
	parsed, _, rest, err := parseSSEEvent(serialized)
	require.NoError(t, err)
	require.NotNil(t, parsed)
	assert.Empty(t, rest)
	assert.Equal(t, original.Event, parsed.Event)
	assert.Equal(t, original.Data, parsed.Data)
	assert.Equal(t, original.ID, parsed.ID)
	assert.Equal(t, original.Retry, parsed.Retry)
}

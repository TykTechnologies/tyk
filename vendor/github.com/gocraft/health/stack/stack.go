package stack

import (
	"bytes"
	"runtime"
)

// MaxStackDepth is the maximum number of stackframes on any error.
var MaxStackDepth = 50

type Trace struct {
	stack  []uintptr
	frames []Frame
}

func NewTrace(skip int) *Trace {
	stack := make([]uintptr, MaxStackDepth)
	length := runtime.Callers(2+skip, stack)
	return &Trace{
		stack: stack[:length],
	}
}

// StackFrames returns an array of frames containing information about the stack.
func (t *Trace) Frames() []Frame {
	if t.frames == nil {
		t.frames = make([]Frame, len(t.stack))

		for i, pc := range t.stack {
			t.frames[i] = NewFrame(pc)
		}
	}

	return t.frames
}

// Stack returns a formatted callstack.
func (t *Trace) Stack() []byte {
	buf := bytes.Buffer{}

	for _, frame := range t.Frames() {
		buf.WriteString(frame.String())
		buf.WriteRune('\n')
	}

	return buf.Bytes()
}

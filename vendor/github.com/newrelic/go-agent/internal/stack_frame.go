// +build go1.7

package internal

import "runtime"

func (st StackTrace) frames() []stacktraceFrame {
	if len(st) == 0 {
		return nil
	}
	frames := runtime.CallersFrames(st) // CallersFrames is only available in Go 1.7+
	fs := make([]stacktraceFrame, 0, maxStackTraceFrames)
	var frame runtime.Frame
	more := true
	for more {
		frame, more = frames.Next()
		fs = append(fs, stacktraceFrame{
			Name: frame.Function,
			File: frame.File,
			Line: int64(frame.Line),
		})
	}
	return fs
}

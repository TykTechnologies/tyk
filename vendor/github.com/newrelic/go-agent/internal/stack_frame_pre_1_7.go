// +build !go1.7

package internal

import "runtime"

func (st StackTrace) frames() []stacktraceFrame {
	fs := make([]stacktraceFrame, len(st))
	for idx, pc := range st {
		fs[idx] = lookupFrame(pc)
	}
	return fs
}

func lookupFrame(pc uintptr) stacktraceFrame {
	// The Golang runtime package documentation says "To look up the file
	// and line number of the call itself, use pc[i]-1. As an exception to
	// this rule, if pc[i-1] corresponds to the function runtime.sigpanic,
	// then pc[i] is the program counter of a faulting instruction and
	// should be used without any subtraction."
	//
	// TODO: Fully understand when this subtraction is necessary.
	place := pc - 1
	f := runtime.FuncForPC(place)
	if nil == f {
		return stacktraceFrame{}
	}
	file, line := f.FileLine(place)
	return stacktraceFrame{
		Name: f.Name(),
		File: file,
		Line: int64(line),
	}
}

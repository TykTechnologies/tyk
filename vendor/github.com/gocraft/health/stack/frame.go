package stack

import (
	// "bytes"
	"fmt"
	// "io/ioutil"
	"runtime"
	"strings"
)

// Frame contains all necessary information about to generate a line in a callstack.
type Frame struct {
	File            string
	LineNumber      int
	Name            string
	Package         string
	IsSystemPackage bool
	ProgramCounter  uintptr
}

// NewFrame popoulates a stack frame object from the program counter.
func NewFrame(pc uintptr) Frame {
	frame := Frame{ProgramCounter: pc}
	if frame.Func() == nil {
		return frame
	}
	frame.Package, frame.Name = packageAndName(frame.Func())

	// pc -1 because the program counters we use are usually return addresses,
	// and we want to show the line that corresponds to the function call
	frame.File, frame.LineNumber = frame.Func().FileLine(pc - 1)
	frame.IsSystemPackage = isSystemPackage(frame.File, frame.Package)

	return frame
}

// Func returns the function that this stackframe corresponds to
func (frame *Frame) Func() *runtime.Func {
	if frame.ProgramCounter == 0 {
		return nil
	}
	return runtime.FuncForPC(frame.ProgramCounter)
}

func (frame *Frame) String() string {
	return fmt.Sprintf("%s:%d %s", frame.File, frame.LineNumber, frame.Name)
}

func packageAndName(fn *runtime.Func) (string, string) {
	name := fn.Name()
	pkg := ""

	// we first remove the path prefix if there is one.
	if lastslash := strings.LastIndex(name, "/"); lastslash >= 0 {
		pkg += name[:lastslash] + "/"
		name = name[lastslash+1:]
	}
	if period := strings.Index(name, "."); period >= 0 {
		pkg += name[:period]
		name = name[period+1:]
	}

	return pkg, name
}

var goroot = runtime.GOROOT()

// isSystemPackage returns true iff the package is a system package like 'runtime' or 'net/http'
func isSystemPackage(file, pkg string) bool {
	return strings.HasPrefix(file, goroot)
}

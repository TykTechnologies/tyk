package gateway

// JSRunner abstracts JS expression execution across otto and goja VM engines.
// Callers build a JS expression string, call Run(), and get back the
// stringified result. Implementations handle timeout, VM lifecycle, and
// panic recovery internally.
type JSRunner interface {
	// Run executes a JS expression and returns its string result.
	Run(expr string) (string, error)

	// Ready reports whether the VM has been initialized and is usable.
	Ready() bool
}

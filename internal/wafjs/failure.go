package wafjs

import (
	"errors"
	"strings"
)

// FailureKind classifies every failure the wafjs host can return. The
// vocabulary covers the full host lifecycle; later beads (body ABI, bounded
// execution, pooling) raise the kinds this skeleton defines.
type FailureKind string

// The typed failure vocabulary.
const (
	// FailureKindConfiguration rejects structurally invalid Build input.
	FailureKindConfiguration FailureKind = "configuration"
	// FailureKindBuild rejects artifacts failing validation or compilation.
	FailureKindBuild FailureKind = "build"
	// FailureKindSnapshot rejects structurally invalid request snapshots.
	FailureKindSnapshot FailureKind = "snapshot"
	// FailureKindBody reports request-body read or limit failures.
	FailureKindBody FailureKind = "body"
	// FailureKindDeadline reports context cancellation or inspection
	// timeouts.
	FailureKindDeadline FailureKind = "deadline"
	// FailureKindExecution reports inspection state-cap overruns.
	FailureKindExecution FailureKind = "execution"
	// FailureKindJavaScript reports engine runtime failures during an
	// inspection.
	FailureKindJavaScript FailureKind = "javascript"
	// FailureKindDecoding rejects engine output that is not a documented
	// Finding.
	FailureKindDecoding FailureKind = "decoding"
	// FailureKindPool reports engine lifecycle and runtime-acquisition
	// failures.
	FailureKindPool FailureKind = "pool"
	// FailureKindInternal reports contained host invariants that should be
	// reported, not trusted.
	FailureKindInternal FailureKind = "internal"
)

// FailureSource names the rejecting artifact or stage of a failure.
type FailureSource string

// Build failure sources. A build failure carries exactly one of these.
const (
	FailureSourceSchema  FailureSource = "schema"
	FailureSourceVersion FailureSource = "version"
	FailureSourcePin     FailureSource = "pin"
	FailureSourceDigest  FailureSource = "digest"
	FailureSourceSize    FailureSource = "size"
	FailureSourcePath    FailureSource = "path"
	FailureSourceCompile FailureSource = "compile"
	FailureSourceABI     FailureSource = "abi"
)

// Failure is the typed error every wafjs host method returns. Callers
// classify failures with errors.As on *Failure; no other error type crosses
// the package API.
type Failure struct {
	// Kind is the failure vocabulary entry.
	Kind FailureKind
	// Source names the rejecting artifact or stage; empty when the kind
	// needs no source.
	Source FailureSource
	// Reason is a short stable token identifying the precise cause.
	Reason string
	// Err is the underlying error, if any.
	Err error
}

// Error implements error with kind, source, reason, and detail.
func (f *Failure) Error() string {
	var b strings.Builder
	b.WriteString("wafjs: ")
	b.WriteString(string(f.Kind))
	if f.Source != "" {
		b.WriteString("/")
		b.WriteString(string(f.Source))
	}
	if f.Reason != "" {
		b.WriteString(": ")
		b.WriteString(f.Reason)
	}
	if f.Err != nil {
		b.WriteString(": ")
		b.WriteString(f.Err.Error())
	}
	return b.String()
}

// Unwrap exposes the underlying error for errors.Is and errors.As chains.
func (f *Failure) Unwrap() error {
	return f.Err
}

// newFailure builds a typed failure.
func newFailure(kind FailureKind, source FailureSource, reason string, err error) *Failure {
	return &Failure{Kind: kind, Source: source, Reason: reason, Err: err}
}

// AsFailure extracts the typed failure from err, if any.
func AsFailure(err error) (*Failure, bool) {
	var f *Failure
	if errors.As(err, &f) {
		return f, true
	}
	return nil, false
}

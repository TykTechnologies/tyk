package newrelic

// StackTracer is type that can be implemented by errors to provide a stack
// trace when using Transaction.NoticeError.
type StackTracer interface {
	StackTrace() []uintptr
}

// ErrorClasser is type that can be implemented by errors to provide a custom
// class when using Transaction.NoticeError.
type ErrorClasser interface {
	ErrorClass() string
}

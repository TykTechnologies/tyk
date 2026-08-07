package errpack

var (
	ErrNotImplemented = New("not implemented", WithType(TypeDomain))
)

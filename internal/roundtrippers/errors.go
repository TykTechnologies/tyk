package roundtrippers

import "errors"

var (
	ErrHeadersTimeout = errors.New("timeout awaiting response headers")
)

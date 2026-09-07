package result

type Result[T any] struct {
	value T
	err   error
}

func New[T any](value T, err error) Result[T] {
	return Result[T]{
		err:   err,
		value: value,
	}
}

func Ok[T any](value T) Result[T] {
	return Result[T]{
		err:   nil,
		value: value,
	}
}

func Err[T any](err error) Result[T] {
	if err == nil {
		panic("result: Err called with nil error")
	}

	return Result[T]{
		err: err,
	}
}

func (r *Result[T]) Get() (T, error) {
	return r.value, r.err
}

func (r *Result[T]) MustGet() T {
	if r.err != nil {
		panic(r.err)
	}

	return r.value
}

func (r *Result[T]) IsError() bool {
	return r.err != nil
}

func (r *Result[T]) IsOk() bool {
	return r.err == nil
}

package pathnormalizer

type collisionError struct {
	a, b Entry
}

func newCollisionError(a, b Entry) collisionError {
	return collisionError{
		a: a,
		b: b,
	}
}

func (c collisionError) Error() string {
	return "collision detected"
}

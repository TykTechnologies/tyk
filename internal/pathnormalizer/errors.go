package pathnormalizer

import "fmt"

var (
	collisionAtExtended    = collisionErrorType{"extended"}
	collisionAtNormalized  = collisionErrorType{"normalized"}
	collisionAtOperationId = collisionErrorType{"operationId"}
)

type collisionErrorType struct {
	name string
}
type collisionError struct {
	existent, new Entry
	loc           collisionErrorType
}

func newCollisionError(existent, next Entry, loc collisionErrorType) collisionError {
	return collisionError{
		existent: existent,
		new:      next,
		loc:      loc,
	}
}

func (c collisionError) at() string {
	return c.loc.name
}

func (c collisionError) Error() string {
	return fmt.Sprintf("collision detected (%s) existent=%#v next%#v", c.at(), c.existent, c.new)
}

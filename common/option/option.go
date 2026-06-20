package option

type (
	Option[O any] func(*O)

	Options[O any] []Option[O]

	FailableOption[O any] func(*O) error
)

// SW-REQ-110
func New[O any](opts []Option[O]) Options[O] {
	return opts
}

// SW-REQ-110
func (o Options[O]) Build(baseVal O) *O {
	for _, apply := range o {
		apply(&baseVal)
	}

	return &baseVal
}

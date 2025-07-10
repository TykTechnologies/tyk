package option

type (
	Option[O any] func(*O)

	Options[O any] []Option[O]

	FailableOption[O any] func(*O) error
)

// New options instance.
func New[O any](opts []Option[O]) Options[O] {
	return opts
}

// Prepend adds options at the beginning of the list.
// Can be used for adding default options.
func (o Options[O]) Prepend(opts ...Option[O]) Options[O] {
	return append(opts, o...)
}

func (o Options[O]) Build(baseVal O) *O {
	for _, apply := range o {
		apply(&baseVal)
	}

	return &baseVal
}

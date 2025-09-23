package option

type (
	Option[O any] func(*O)

	Options[O any] []Option[O]
)

func New[O any](opts []Option[O]) Options[O] {
	return opts
}

func (o Options[O]) Build(baseVal O) *O {
	for _, apply := range o {
		apply(&baseVal)
	}

	return &baseVal
}

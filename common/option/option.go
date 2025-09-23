package option

type (
	Option[O any] func(*O)

	Options[O any] []Option[O]

	FailableOption[O any] func(*O) error

	FailableOptions[O any] []FailableOption[O]
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

func NewFailable[O any](opts []FailableOption[O]) FailableOptions[O] {
	return opts
}

func (o FailableOptions[O]) Build(baseVal O) (*O, error) {
	for _, apply := range o {
		if err := apply(&baseVal); err != nil {
			return nil, err
		}
	}

	return &baseVal, nil
}

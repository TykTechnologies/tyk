package postprocess

import (
	"github.com/jensneuse/graphql-go-tools/pkg/engine/plan"
)

type PostProcessor interface {
	Process(pre plan.Plan) plan.Plan
}

type Processor struct {
	postProcessors []PostProcessor
}

func DefaultProcessor() *Processor {
	return &Processor{
		[]PostProcessor{
			&ProcessDefer{},
			&ProcessStream{},
			&ProcessDataSource{},
		},
	}
}

func (p *Processor) Process(pre plan.Plan) (post plan.Plan) {
	post = pre
	for i := range p.postProcessors {
		post = p.postProcessors[i].Process(post)
	}
	return
}

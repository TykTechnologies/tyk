package execution

import (
	"bytes"

	"github.com/jensneuse/pipeline/pkg/pipe"
)

type Transformation interface {
	Transform(input []byte) ([]byte, error)
}

type PipelineTransformation struct {
	pipeline pipe.Pipeline
	buf      bytes.Buffer
}

func (p *PipelineTransformation) Transform(input []byte) ([]byte, error) {
	p.buf.Reset()
	err := p.pipeline.Run(bytes.NewReader(input), &p.buf)
	return p.buf.Bytes(), err
}

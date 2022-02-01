package graphql_datasource

import (
	"bytes"
	"fmt"

	"github.com/buger/jsonparser"

	"github.com/jensneuse/graphql-go-tools/pkg/engine/resolve"
	"github.com/jensneuse/graphql-go-tools/pkg/fastbuffer"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
	"github.com/jensneuse/graphql-go-tools/pkg/pool"
)

var representationPath = []string{"body", "variables", "representations"}

type Batch struct {
	resultedInput    *fastbuffer.FastBuffer
	responseMappings []inputResponseBufferMappings
	batchSize        int
}

// inputResponseBufferMappings defines the relationship between input containing an _entities Query
// and the output buffers, the response needs to be mapped to
type inputResponseBufferMappings struct {
	// responseIndex is the array position of the response
	responseIndex int
	// originalInput is the original input of a response to allow comparing and deduplication
	originalInput []byte
	// assignedBufferIndices are the buffers to which the response needs to be assigned
	assignedBufferIndices []int
}

func NewBatchFactory() *BatchFactory {
	return &BatchFactory{}
}

type BatchFactory struct{}

func (b *BatchFactory) CreateBatch(inputs [][]byte) (resolve.DataSourceBatch, error) {
	if len(inputs) == 0 {
		return nil, nil
	}

	resultedInput := pool.FastBuffer.Get()

	responseMappings, err := b.multiplexBatch(resultedInput, inputs)
	if err != nil {
		return nil, nil
	}

	return &Batch{
		resultedInput:    resultedInput,
		responseMappings: responseMappings,
		batchSize:        len(inputs),
	}, nil
}

func (b *Batch) Input() *fastbuffer.FastBuffer {
	return b.resultedInput
}

func (b *Batch) Demultiplex(responseBufPair *resolve.BufPair, bufPairs []*resolve.BufPair) (err error) {
	defer pool.FastBuffer.Put(b.resultedInput)

	if b.batchSize != len(bufPairs) {
		return fmt.Errorf("expected %d buf pairs", b.batchSize)
	}

	if err = b.demultiplexBatch(responseBufPair, b.responseMappings, bufPairs); err != nil {
		return err
	}

	return
}

func (b *BatchFactory) multiplexBatch(out *fastbuffer.FastBuffer, inputs [][]byte) (responseMappings []inputResponseBufferMappings, err error) {
	if len(inputs) == 0 {
		return nil, nil
	}

	variablesBuf := pool.FastBuffer.Get()
	defer pool.FastBuffer.Put(variablesBuf)

	variablesBuf.WriteBytes(literal.LBRACK)

	var (
		variablesIdx              int
		firstRepresentationsStart int
		firstRepresentationsEnd   int
	)

	for i := range inputs {
		inputVariables, _, representationsOffset, err := jsonparser.Get(inputs[i], representationPath...)
		if err != nil {
			return nil, err
		}

		if i == 0 {
			firstRepresentationsStart = representationsOffset - len(inputVariables)
			firstRepresentationsEnd = representationsOffset
		}

		_, err = jsonparser.ArrayEach(inputVariables, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {

			for j := range responseMappings {
				existing := responseMappings[j].originalInput
				if bytes.Equal(existing, value) {
					responseMappings[j].assignedBufferIndices = append(responseMappings[j].assignedBufferIndices, i)
					return
				}
			}

			if variablesBuf.Len() != 1 {
				variablesBuf.WriteBytes(literal.COMMA)
			}
			variablesBuf.WriteBytes(value)

			responseMappings = append(responseMappings, inputResponseBufferMappings{
				responseIndex:         variablesIdx,
				originalInput:         value,
				assignedBufferIndices: []int{i},
			})

			variablesIdx++
		})
		if err != nil {
			return nil, err
		}
	}

	variablesBuf.WriteBytes(literal.RBRACK)

	representationJson := variablesBuf.Bytes()
	representationJsonCopy := make([]byte, len(representationJson))
	copy(representationJsonCopy, representationJson)

	header := inputs[0][0:firstRepresentationsStart]
	trailer := inputs[0][firstRepresentationsEnd:]

	out.WriteBytes(header)
	out.WriteBytes(representationJsonCopy)
	out.WriteBytes(trailer)

	return
}

func (b *Batch) demultiplexBatch(responsePair *resolve.BufPair, responseMappings []inputResponseBufferMappings, resultBufPairs []*resolve.BufPair) (err error) {
	var outPosition int

	if responsePair.HasData() {
		_, err = jsonparser.ArrayEach(responsePair.Data.Bytes(), func(value []byte, dataType jsonparser.ValueType, offset int, err error) {

			if outPosition > len(responseMappings)+1 {
				return
			}

			mapping := responseMappings[outPosition]

			for _, index := range mapping.assignedBufferIndices {
				if resultBufPairs[index].Data.Len() != 0 {
					resultBufPairs[index].Data.WriteBytes(literal.COMMA)
				}
				resultBufPairs[index].Data.WriteBytes(value)
			}

			outPosition++
		})
		if err != nil {
			return err
		}
	}

	if responsePair.HasErrors() {
		resultBufPairs[0].Errors.WriteBytes(responsePair.Errors.Bytes())
	}

	return
}

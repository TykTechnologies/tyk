package subscription

import (
	"bytes"
	"context"
	"sync"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/resolve"
	"github.com/jensneuse/graphql-go-tools/pkg/graphql"
)

type ExecutorV2Pool struct {
	engine       *graphql.ExecutionEngineV2
	executorPool *sync.Pool
}

func NewExecutorV2Pool(engine *graphql.ExecutionEngineV2) *ExecutorV2Pool {
	return &ExecutorV2Pool{
		engine: engine,
		executorPool: &sync.Pool{
			New: func() interface{} {
				return &ExecutorV2{}
			},
		},
	}
}

func (e *ExecutorV2Pool) Get(payload []byte) (Executor, error) {
	operation := graphql.Request{}
	err := graphql.UnmarshalRequest(bytes.NewReader(payload), &operation)
	if err != nil {
		return nil, err
	}

	return &ExecutorV2{
		engine:    e.engine,
		operation: &operation,
		context:   context.Background(),
	}, nil
}

func (e *ExecutorV2Pool) Put(executor Executor) error {
	executor.Reset()
	e.executorPool.Put(executor)
	return nil
}

type ExecutorV2 struct {
	engine    *graphql.ExecutionEngineV2
	operation *graphql.Request
	context   context.Context
}

func (e *ExecutorV2) Execute(writer resolve.FlushWriter) error {
	return e.engine.Execute(e.context, e.operation, writer)
}

func (e *ExecutorV2) OperationType() ast.OperationType {
	opType, err := e.operation.OperationType()
	if err != nil {
		return ast.OperationTypeUnknown
	}

	return ast.OperationType(opType)
}

func (e *ExecutorV2) SetContext(context context.Context) {
	e.context = context
}

func (e *ExecutorV2) Reset() {
	e.engine = nil
	e.operation = nil
	e.context = context.Background()
}

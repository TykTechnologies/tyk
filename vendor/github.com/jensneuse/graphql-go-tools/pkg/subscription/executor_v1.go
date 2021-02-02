package subscription

import (
	"context"
	"sync"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/resolve"
	"github.com/jensneuse/graphql-go-tools/pkg/execution"
)

type ExecutorV1Pool struct {
	ExecutionHandler *execution.Handler
	executorPool     *sync.Pool
}

func NewExecutorV1Pool(executionHandler *execution.Handler) *ExecutorV1Pool {
	return &ExecutorV1Pool{
		ExecutionHandler: executionHandler,
		executorPool: &sync.Pool{
			New: func() interface{} {
				return &ExecutorV1{}
			},
		},
	}
}

func (e *ExecutorV1Pool) Get(payload []byte) (Executor, error) {
	engineExecutor, node, executionContext, err := e.ExecutionHandler.Handle(payload, []byte(""))
	if err != nil {
		return nil, err
	}

	executor := e.executorPool.Get().(*ExecutorV1)
	executor.engineExecutor = engineExecutor
	executor.rootNode = node
	executor.executionContext = executionContext

	return executor, nil
}

func (e *ExecutorV1Pool) Put(executor Executor) error {
	executor.Reset()
	e.executorPool.Put(executor)
	return nil
}

type ExecutorV1 struct {
	engineExecutor   *execution.Executor
	rootNode         execution.RootNode
	executionContext execution.Context
}

func (e *ExecutorV1) Execute(writer resolve.FlushWriter) error {
	return e.engineExecutor.Execute(e.executionContext, e.rootNode, writer)
}

func (e *ExecutorV1) OperationType() ast.OperationType {
	return e.rootNode.OperationType()
}

func (e *ExecutorV1) SetContext(context context.Context) {
	e.executionContext.Context = context
}

func (e *ExecutorV1) Reset() {
	e.engineExecutor = nil
	e.rootNode = nil
	e.executionContext = execution.Context{}
}

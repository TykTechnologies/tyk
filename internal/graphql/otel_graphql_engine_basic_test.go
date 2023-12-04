package graphql

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/mock/gomock"

	semconv "github.com/TykTechnologies/opentelemetry/semconv/v1.0.0"
)

func TestOtelGraphqlEngineV2Basic_Execute(t *testing.T) {
	t.Run("successfully execute", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().Execute(gomock.Any(), &request, nil).MaxTimes(1).Return(nil)
		engine, err := NewOtelGraphqlEngineV2Basic(tracerProvider, mockExecutor)
		engine.executor = mockExecutor
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		err = engine.Execute(context.Background(), &request, nil)
		assert.NoError(t, err)
	})

	t.Run("fail execute", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		expectedErr := errors.New("error executing request")
		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().Execute(gomock.Any(), &request, nil).MaxTimes(1).Return(expectedErr)

		engine, err := NewOtelGraphqlEngineV2Basic(tracerProvider, mockExecutor)
		assert.NoError(t, err)
		engine.executor = mockExecutor
		engine.SetContext(context.Background())

		err = engine.Execute(context.Background(), &request, nil)
		assert.ErrorIs(t, err, expectedErr)
	})
}

func TestOtelGraphqlEngineV2Basic_Execute_SemanticConventionAttributes(t *testing.T) {
	checkStringAttribute := func(attributes []attribute.KeyValue, name attribute.Key, expectedValue string) {
		for _, attr := range attributes {
			if attr.Key == name {
				assert.Equal(t, attr.Value.AsString(), expectedValue)
				return
			}
		}
		assert.Failf(t, "attribute not found", string(name))
	}

	t.Run("successfully execute", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().Execute(gomock.Any(), &namedRequest, nil).MaxTimes(1).Return(nil)

		wrappedTraceProvider := newTracerProviderWrapper(tracerProvider)
		engine, err := NewOtelGraphqlEngineV2Basic(wrappedTraceProvider, mockExecutor)
		engine.executor = mockExecutor
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		err = engine.Execute(context.Background(), &namedRequest, nil)
		assert.NoError(t, err)

		attributes := wrappedTraceProvider.spanAttributes["GraphqlEngine"]
		assert.NotNil(t, attributes)

		checkStringAttribute(attributes, semconv.GraphQLOperationNameKey, namedRequest.OperationName)
		checkStringAttribute(attributes, semconv.GraphQLOperationTypeKey, "query")
		checkStringAttribute(attributes, semconv.GraphQLDocumentKey, namedRequest.Query)
	})
}

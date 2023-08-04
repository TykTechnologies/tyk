package graphql

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/resolve"
	"github.com/TykTechnologies/graphql-go-tools/pkg/operationreport"
	"github.com/TykTechnologies/graphql-go-tools/pkg/postprocess"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/TykTechnologies/tyk-pump/logger"
	"github.com/TykTechnologies/tyk/internal/otel"
)

var request = graphql.Request{
	Query: `{
  country(code: "NG"){
    name
  }
}`,
}

var tracerProvider otel.TracerProvider

func TestMain(m *testing.M) {
	//use noop tracer exporter
	tracerProvider = otel.InitOpenTelemetry(context.Background(), logger.GetLogger(), &otel.Config{
		Enabled:  true,
		Exporter: "invalid",
	}, "test", "test", false, "", false, []string{})
	exitVal := m.Run()
	os.Exit(exitVal)
}

func TestOtelGraphqlEngineV2_Normalize(t *testing.T) {
	t.Run("successfully normalize", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().Normalize(gomock.Any()).MaxTimes(1).Return(nil)

		engine, err := NewOtelGraphqlEngineV2(tracerProvider, mockExecutor)
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		err = engine.Normalize(&request)
		assert.NoError(t, err)
	})

	t.Run("fail normalize", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().Normalize(gomock.Any()).MaxTimes(1).Return(graphql.RequestErrorsFromError(errors.New("error normalizing request")))

		engine, err := NewOtelGraphqlEngineV2(tracerProvider, mockExecutor)
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		err = engine.Normalize(&request)
		var reqErr graphql.RequestErrors
		assert.True(t, errors.As(err, &reqErr), "errors should be of type request errors")

	})

}

func TestOtelGraphqlEngineV2_Setup(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockExecutor := NewMockExecutionEngineI(ctrl)
	mockExecutor.EXPECT().Setup(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).MaxTimes(1)
	engine, err := NewOtelGraphqlEngineV2(tracerProvider, mockExecutor)
	assert.NoError(t, err)
	engine.SetContext(context.Background())

	engine.Setup(context.Background(), nil, nil, &request)
	assert.NoError(t, err)
}

func TestOtelGraphqlEngineV2_InputValidation(t *testing.T) {
	t.Run("successfully validate", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().InputValidation(gomock.Any()).MaxTimes(1).Return(nil)

		engine, err := NewOtelGraphqlEngineV2(tracerProvider, mockExecutor)
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		err = engine.InputValidation(&request)
		assert.NoError(t, err)
	})

	t.Run("fail input validation", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().InputValidation(gomock.Any()).MaxTimes(1).Return(graphql.RequestErrorsFromError(errors.New("error normalizing request")))

		engine, err := NewOtelGraphqlEngineV2(tracerProvider, mockExecutor)
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		err = engine.InputValidation(&request)
		var reqErr graphql.RequestErrors
		assert.True(t, errors.As(err, &reqErr), "errors should be of type request errors")

	})
}

func TestOtelGraphqlEngineV2_ValidateForSchema(t *testing.T) {
	t.Run("successfully validate", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().ValidateForSchema(gomock.Any()).MaxTimes(1).Return(nil)

		engine, err := NewOtelGraphqlEngineV2(tracerProvider, mockExecutor)
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		err = engine.ValidateForSchema(&request)
		assert.NoError(t, err)
	})

	t.Run("fail validation", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().ValidateForSchema(gomock.Any()).MaxTimes(1).Return(graphql.RequestErrorsFromError(errors.New("error normalizing request")))

		engine, err := NewOtelGraphqlEngineV2(tracerProvider, mockExecutor)
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		err = engine.ValidateForSchema(&request)
		var reqErr graphql.RequestErrors
		assert.True(t, errors.As(err, &reqErr), "errors should be of type request errors")

	})
}

func TestOtelGraphqlEngineV2_Plan(t *testing.T) {
	t.Run("failed to generate plan", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockExecutor := NewMockExecutionEngineI(ctrl)
		var report operationreport.Report
		mockExecutor.EXPECT().Plan(gomock.Any(), gomock.Any(), &report).MaxTimes(1).Return(nil, nil).Do(
			func(postProcessor *postprocess.Processor, operation *graphql.Request, report *operationreport.Report) {
				report.AddExternalError(operationreport.ExternalError{Message: "error creating plan"})
			})

		engine, err := NewOtelGraphqlEngineV2(tracerProvider, mockExecutor)
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		_, err = engine.Plan(nil, &request, &report)
		assert.NoError(t, err)
		assert.True(t, report.HasErrors(), "expected error from operation report, got none")
	})

	t.Run("successfully generate plan", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		var report operationreport.Report
		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().Plan(gomock.Any(), gomock.Any(), &report).MaxTimes(1).Return(nil, nil)

		engine, err := NewOtelGraphqlEngineV2(tracerProvider, mockExecutor)
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		_, err = engine.Plan(nil, &request, &report)
		assert.NoError(t, err)
		assert.False(t, report.HasErrors())
	})

	t.Run("return error generating plan", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		var report operationreport.Report
		expectedErr := errors.New("error generating plan")
		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().Plan(gomock.Any(), gomock.Any(), &report).MaxTimes(1).Return(nil, expectedErr)

		engine, err := NewOtelGraphqlEngineV2(tracerProvider, mockExecutor)
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		_, err = engine.Plan(nil, &request, &report)
		assert.ErrorIs(t, expectedErr, err)
		assert.False(t, report.HasErrors())
	})
}

func TestOtelGraphqlEngineV2_Resolve(t *testing.T) {
	t.Run("successfully resolve", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().Resolve(gomock.Any(), gomock.Any(), nil).MaxTimes(1).Return(nil)

		engine, err := NewOtelGraphqlEngineV2(tracerProvider, mockExecutor)
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		err = engine.Resolve(&resolve.Context{}, nil, nil)
		assert.NoError(t, err)
	})

	t.Run("fail resolve", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		expectedErr := errors.New("error resolving request")
		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().Resolve(gomock.Any(), gomock.Any(), nil).MaxTimes(1).Return(expectedErr)

		engine, err := NewOtelGraphqlEngineV2(tracerProvider, mockExecutor)
		assert.NoError(t, err)
		engine.SetContext(context.Background())

		err = engine.Resolve(&resolve.Context{}, nil, nil)
		assert.ErrorIs(t, err, expectedErr)
	})
}

func TestOtelGraphqlEngineV2_Execute(t *testing.T) {
	t.Run("successfully execute", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockExecutor := NewMockExecutionEngineI(ctrl)
		mockExecutor.EXPECT().Execute(gomock.Any(), &request, nil).MaxTimes(1).Return(nil)
		engine, err := NewOtelGraphqlEngineV2(tracerProvider, mockExecutor)
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

		engine, err := NewOtelGraphqlEngineV2(tracerProvider, mockExecutor)
		assert.NoError(t, err)
		engine.executor = mockExecutor
		engine.SetContext(context.Background())

		err = engine.Execute(context.Background(), &request, nil)
		assert.ErrorIs(t, err, expectedErr)
	})
}

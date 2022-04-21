package dnscache

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/TykTechnologies/tyk/test"
)

func TestMain(m *testing.M) {
	os.Exit(InitTestMain(context.Background(), m))
}

var (
	dnsMock *test.DnsMockHandle
)

func InitTestMain(ctx context.Context, m *testing.M) int {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := setUp(ctx); err != nil {
		logger.WithError(err).Error()
	}
	defer func() {
		if err := tearDown(); err != nil {
			logger.WithError(err).Error()
		}
	}()

	return m.Run()
}

func setUp(ctx context.Context) (err error) {
	dnsMock, err = test.InitDNSMock(etcHostsMap, etcHostsErrorMap)
	if err != nil {
		return fmt.Errorf("Error in dns mock init: %w", err)
	}

	return nil
}

func tearDown() error {
	if err := dnsMock.Shutdown(); err != nil {
		return err
	}

	return nil
}

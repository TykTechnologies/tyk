package storage

import (
	"context"
	"os"
	"strconv"
	"time"

	"github.com/TykTechnologies/tyk/config"
)

func rcConfig() *config.Config {
	c := config.Default

	// Override defaults to enable testing non-default drivers
	if val := os.Getenv("TEST_STORAGE_TYPE"); val != "" {
		c.Storage.Type = val
	}
	if val := os.Getenv("TEST_STORAGE_HOST"); val != "" {
		c.Storage.Host = val
	}
	if val, err := strconv.Atoi(os.Getenv("TEST_STORAGE_PORT")); err == nil {
		c.Storage.Port = val
	}

	return &c
}

func rc(ctx context.Context, cfg *config.Config) (rc *RedisController) {
	if cfg == nil {
		cfg = rcConfig()
	}

	rc = NewRedisController(ctx)
	go rc.Connect(ctx, nil, cfg)

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if !rc.WaitConnect(ctx) {
		panic("can't connect to redis, timeout")
	}
	return
}

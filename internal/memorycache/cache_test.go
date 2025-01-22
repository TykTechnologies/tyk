package memorycache

import (
	"context"
	"testing"
	"time"
)

func TestCache_Shutdown(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	cache := NewCache(ctx, time.Minute)
	_ = cache.Get
}

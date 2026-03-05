package metrics

import (
	"net/http"

	"github.com/TykTechnologies/tyk/internal/interfaces"
	"github.com/TykTechnologies/tyk/pkg/errpack"
)

var ErrEmptySecret = errpack.Domain("empty secret")

const (
	defaultNamespace = "tyk_gw"
)

type Metrics interface {
	Handler() http.Handler
	DecorateNotifier(notifier interfaces.Notifier) interfaces.Notifier
	IncrPubSubDisconnect()
}

type Config struct {
	Enabled                 bool              `json:"enabled"`
	Secret                  string            `json:"secret"` // todo: maybe it worth using secret from global config?
	Namespace               string            `json:"namespace"`
	DisableProcessCollector bool              `json:"disable_process_collector"`
	DisableGoCollector      bool              `json:"disable_go_collector"`
	Labels                  map[string]string `json:"labels"`
}

func (c *Config) setDefaults() {
	if c.Namespace == "" {
		c.Namespace = defaultNamespace
	}
}

func New(cfg Config) (Metrics, error) {
	cfg.setDefaults()

	if !cfg.Enabled {
		return &dummy{}, nil
	}

	return newProm(cfg)
}

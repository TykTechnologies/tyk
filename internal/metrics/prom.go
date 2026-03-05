package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/TykTechnologies/tyk/internal/interfaces"
	"github.com/TykTechnologies/tyk/pkg/errpack"
)

func newProm(cfg Config) (*prom, error) {
	if len(cfg.Secret) == 0 {
		return nil, ErrEmptySecret
	}

	p := &prom{
		cfg:      cfg,
		registry: prometheus.NewRegistry(),
	}

	if !cfg.DisableProcessCollector {
		if err := p.registry.Register(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})); err != nil {
			return nil, errpack.New("failed to register process collector").Wrap(err)
		}
	}

	if !cfg.DisableGoCollector {
		if err := p.registry.Register(collectors.NewGoCollector()); err != nil {
			return nil, errpack.New("failed to register go collector").Wrap(err)
		}
	}

	// todo: consult name with management it is crucial because of changing metrics names in prometheus is difficult
	p.pubSubCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name:        "pub_sub_disconnect",
		Namespace:   cfg.Namespace,
		Help:        "Number of disconnections in pub-sub",
		ConstLabels: p.labels(),
	})

	p.notifySuccessCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name:        "notify_success",
		Namespace:   cfg.Namespace,
		Help:        "Number of successfully published notification",
		ConstLabels: p.labels(),
	})

	p.notifyFailCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name:        "notify_failed",
		Namespace:   cfg.Namespace,
		Help:        "Number of failed notification during publish",
		ConstLabels: p.labels(),
	})

	if err := p.registerMany(
		p.pubSubCounter,
		p.notifySuccessCounter,
		p.notifyFailCounter,
	); err != nil {
		return nil, errpack.Infra("failed to register go collector").Wrap(err)
	}

	return p, nil
}

type prom struct {
	registry             *prometheus.Registry
	cfg                  Config
	pubSubCounter        prometheus.Counter
	notifySuccessCounter prometheus.Counter
	notifyFailCounter    prometheus.Counter
}

func (p *prom) Handler() http.Handler {
	return promhttp.HandlerFor(p.registry, promhttp.HandlerOpts{})
}

func (p *prom) DecorateNotifier(notifier interfaces.Notifier) interfaces.Notifier {
	return anonNotifyWrapper(func(notif any) bool {
		res := notifier.Notify(notif)

		if res {
			p.notifySuccessCounter.Inc()
		} else {
			p.notifyFailCounter.Inc()
		}

		return res
	})
}

func (p *prom) IncrPubSubDisconnect() {
	p.pubSubCounter.Inc()
}

func (p *prom) labels() map[string]string {
	return p.cfg.Labels
}

func (p *prom) registerMany(ctrs ...prometheus.Collector) error {
	for _, c := range ctrs {
		if err := p.registry.Register(c); err != nil {
			return err
		}
	}

	return nil
}

type anonNotifyWrapper func(notif any) bool

func (f anonNotifyWrapper) Notify(notif any) bool {
	return f(notif)
}

var _ Metrics = new(prom)

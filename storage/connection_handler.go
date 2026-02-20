package storage

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenk/backoff"

	"github.com/TykTechnologies/storage/temporal/connector"
	"github.com/TykTechnologies/storage/temporal/model"

	"github.com/TykTechnologies/tyk/config"
)

// ConnectionHandler is a wrapper around the storage connection.
// It allows to dynamically enable/disable talking with storage and
// mantain a connection map to different storage types.
type ConnectionHandler struct {
	connections   map[string]model.Connector
	connectionsMu *sync.RWMutex

	storageUp      atomic.Value
	disableStorage atomic.Value

	ctx       context.Context
	reconnect chan struct{}
}

const (
	// DefaultConn is the default connection type. Not analytics and Not cache.
	DefaultConn = "default"
	// CacheConn is the cache connection type
	CacheConn = "cache"
	// AnalyticsConn is the analytics connection type
	AnalyticsConn = "analytics"
)

// NewConnectionHandler creates a new connection handler not connected
func NewConnectionHandler(ctx context.Context) *ConnectionHandler {
	return &ConnectionHandler{
		ctx:           ctx,
		reconnect:     make(chan struct{}, 1),
		connections:   make(map[string]model.Connector),
		connectionsMu: &sync.RWMutex{},
	}
}

// DisableStorage allows to dynamically enable/disable talking with storage
func (rc *ConnectionHandler) DisableStorage(setStorageDown bool) {
	if setStorageDown {
		// we make sure x set that redis is down
		rc.disableStorage.Store(true)
		rc.storageUp.Store(false)
		return
	}

	rc.disableStorage.Store(false)
	rc.storageUp.Store(false)

	ctx, cancel := context.WithTimeout(rc.ctx, 5*time.Second)
	defer cancel()

	if !rc.WaitConnect(ctx) {
		panic("Can't reconnect to redis after disable")
	}
	rc.reconnect <- struct{}{}
}

// Connected returns true if we are connected to redis
func (rc *ConnectionHandler) Connected() bool {
	v := rc.storageUp.Load()
	if v != nil {
		return v.(bool)
	}
	return false
}

// WaitConnect waits until we are connected to the storage
func (rc *ConnectionHandler) WaitConnect(ctx context.Context) bool {
	for {
		select {
		case <-ctx.Done():
			return false
		default:
			if rc.Connected() {
				return true
			}

			time.Sleep(10 * time.Millisecond)
		}
	}
}

func (rc *ConnectionHandler) enabled() bool {
	ok := true
	if v := rc.disableStorage.Load(); v != nil {
		ok = !v.(bool)
	}
	return ok
}

// Disconnect closes the connection to the storage
func (rc *ConnectionHandler) Disconnect() error {
	for _, v := range rc.connections {
		if v != nil {
			if err := v.Disconnect(context.Background()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (rc *ConnectionHandler) recoverLoop(ctx context.Context, onReconnect func()) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-rc.reconnect:
			onReconnect()
		}
	}
}

// Connect starts a go routine that periodically tries to connect to
// storage.
//
// onConnect will be called when we have established a successful storage reconnection
func (rc *ConnectionHandler) Connect(ctx context.Context, onConnect func(), conf *config.Config) {
	if onConnect == nil {
		onConnect = func() {}
	}

	err := rc.initConnection(*conf)
	if err != nil {
		log.WithError(err).Error("Could not initialize connection to Redis cluster")
		return
	}

	// First time connecting to the clusters. We need this for the first connection (and avoid waiting 1second for the rc.statusCheck loop).
	for connTyp, connection := range rc.connections {
		if connection == nil {
			log.Warn("connection" + connTyp + " is nil")
		}
		err := backoff.Retry(func() error { return connection.Ping(ctx) }, getExponentialBackoff())
		if err != nil {
			log.WithError(err).Errorf("Could not connect to Redis cluster after many attempts. Host(s): %v", getRedisAddrs(conf.Storage))
		}
	}

	rc.storageUp.Store(true)
	go rc.recoverLoop(ctx, onConnect)

	// We need the ticker to constantly checking the connection status of Redis. If Redis gets down and up again, we should be able to recover.
	go rc.statusCheck(ctx)
}

// initConnection initializes the connection singletons.
func (rc *ConnectionHandler) initConnection(conf config.Config) (err error) {
	rc.connectionsMu.Lock()
	defer rc.connectionsMu.Unlock()

	connTypes := []string{
		DefaultConn,
		CacheConn,
		AnalyticsConn,
	}

	for _, connType := range connTypes {
		conn, err := NewConnector(connType, conf)
		if err != nil {
			return err
		}
		rc.connections[connType] = conn
	}

	return nil
}

func (rc *ConnectionHandler) isConnected(ctx context.Context, connType string) bool {
	if conn, ok := rc.connections[connType]; ok && conn != nil {
		err := conn.Ping(ctx)
		return err == nil
	}
	return false
}

// statusCheck will check the storage status each second.
// This method will be constantly modifying the redisUp control flag.
func (rc *ConnectionHandler) statusCheck(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			// if we disabled storage - we don't want to check anything
			if !rc.enabled() {
				continue
			}

			// we check if the clusters are initialised and if connections are open
			connected := rc.isConnected(ctx, DefaultConn) && rc.isConnected(ctx, CacheConn) && rc.isConnected(ctx, AnalyticsConn)

			// we check if we are already connected connected
			alreadyConnected := rc.Connected()

			// store the actual status of redis
			rc.storageUp.Store(connected)

			// if we weren't alerady connected but now we are connected, we trigger the reconnect
			if !alreadyConnected && connected {
				rc.reconnect <- struct{}{}
			}

		}
	}
}

func (rc *ConnectionHandler) getConnection(isCache, isAnalytics bool) model.Connector {
	rc.connectionsMu.RLock()
	defer rc.connectionsMu.RUnlock()
	if isAnalytics {
		return rc.connections[AnalyticsConn]
	} else if isCache {
		return rc.connections[CacheConn]
	}
	return rc.connections[DefaultConn]
}

// NewConnector creates a new storage connection.
func NewConnector(connType string, conf config.Config) (model.Connector, error) {
	cfg := conf.Storage
	if connType == CacheConn && conf.EnableSeperateCacheStore {
		cfg = conf.CacheStorage
	} else if connType == AnalyticsConn && conf.EnableAnalytics && conf.EnableSeperateAnalyticsStore {
		cfg = conf.AnalyticsStorage
	}
	log.Debug("Creating new " + connType + " Storage connection")

	// poolSize applies per cluster node and not for the whole cluster.
	poolSize := 500
	if cfg.MaxActive > 0 {
		poolSize = cfg.MaxActive
	}

	timeout := 5
	if cfg.Timeout > 0 {
		timeout = cfg.Timeout
	}

	opts := []model.Option{}
	optsR := model.RedisOptions{
		Username:         cfg.Username,
		Password:         cfg.Password,
		Host:             cfg.Host,
		Port:             cfg.Port,
		Timeout:          timeout,
		Hosts:            cfg.Hosts,
		Addrs:            cfg.Addrs,
		MasterName:       cfg.MasterName,
		SentinelPassword: cfg.SentinelPassword,
		Database:         cfg.Database,
		MaxActive:        poolSize,
		EnableCluster:    cfg.EnableCluster,
	}
	opts = append(opts, model.WithRedisConfig(&optsR))

	if cfg.UseSSL {
		tls := model.TLS{
			Enable:             cfg.UseSSL,
			InsecureSkipVerify: cfg.SSLInsecureSkipVerify,
			CAFile:             cfg.CAFile,
			CertFile:           cfg.CertFile,
			KeyFile:            cfg.KeyFile,
			MinVersion:         cfg.TLSMinVersion,
			MaxVersion:         cfg.TLSMaxVersion,
		}
		opts = append(opts, model.WithTLS(&tls))
	}

	return connector.NewConnector(model.RedisV9Type, opts...)
}

// getExponentialBackoff returns a backoff.ExponentialBackOff with the following settings:
//   - Multiplier: 2
//   - MaxInterval: 10 seconds
//   - MaxElapsedTime: 0 (no limit)
func getExponentialBackoff() *backoff.ExponentialBackOff {
	exponentialBackoff := backoff.NewExponentialBackOff()
	exponentialBackoff.Multiplier = 2
	exponentialBackoff.MaxInterval = 10 * time.Second
	exponentialBackoff.MaxElapsedTime = 0

	return exponentialBackoff
}

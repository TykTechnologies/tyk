package storage

import (
	"context"
	"path/filepath"

	"github.com/TykTechnologies/tyk/api"
	"github.com/TykTechnologies/tyk/config"
	"github.com/dgraph-io/badger/v3"
	"google.golang.org/grpc"
)

var simple nativeDB

type nativeDB struct {
	// rate stores rate limiting data. We rely on versions to achieve
	// rolling window implementation. This requires us to keep lots of versions of
	// the same key, we don't need this for other uses so we manage this
	// differently
	rate *badger.DB

	general *badger.DB

	// A connection to a pubsub server used for notifications
	pubsub api.PubSubClient

	// analytics a grpc sync to which we send analytics records
	analytics     api.AnalyticsSync_SyncClient
	analyticsConn *grpc.ClientConn
}

func (n *nativeDB) Close() {
	if n.general != nil {
		n.general.Close()
	}
	if n.rate != nil {
		n.rate.Close()
	}
	if n.analytics != nil {
		n.analytics.CloseSend()
	}
	if n.analyticsConn != nil {
		n.analyticsConn.Close()
	}
}

func SetupNative() {
	g := config.Global()
	if g.Storage.Type == "native" {
		// create general database
		{
			log.Info(" setting up global storage")
			path := filepath.Join(g.Storage.Host, "general")

			o := badger.DefaultOptions(path)
			o.Logger = nativeLog
			db, err := badger.Open(o)
			if err != nil {
				// This is fatal if we can't open the database we need to make sure we have
				// a working database to proceed
				log.Fatal("Failed to setup general database", err)
			}
			simple.general = db
		}
		{
			log.Info(" setting up rate limiters storage")
			path := filepath.Join(g.Storage.Host, "rates")
			o := badger.DefaultOptions(path)
			o.Logger = nativeLog
			// Tunable value for rolling window use.
			o.NumVersionsToKeep = 200
			db, err := badger.Open(o)
			if err != nil {
				// This is fatal if we can't open the database we need to make sure we have
				// a working database to proceed
				nativeLog.Fatal("Failed to setup rates limiting database", err)
			}
			simple.rate = db
		}
		if g.EnableAnalytics {
			// setup grpc server to push analytics to
			conn, err := grpc.Dial(g.AnalyticsStorage.Host, grpc.WithInsecure())
			if err != nil {
				nativeLog.Fatal("Failed to establish connection with analytics grpc server", err)
			}
			simple.analyticsConn = conn
			ac := api.NewAnalyticsSyncClient(conn)
			nativeLog.Info("preparing analytics sync")
			sink, err := ac.Sync(context.Background())
			if err != nil {
				nativeLog.Fatal("Failed to open sync stream to analytics service", err)
			}
			simple.analytics = sink
		}
		nativeLog.Info("Native store is ready")
	}
}

func TearDownNative() {
	g := config.Global().Storage
	if g.Type == "native" {
		nativeLog.Info("closing  storage databases")
		simple.Close()
	}
}

var _ Handler = (*Native)(nil)

type Native struct {
	Options
}

func (n Native) Connect() bool {
	return true
}

func (n Native) SetRollingWindow(key string, per int64, val string, pipeline bool) (int, []interface{}) {
	return (&rate{db: simple.rate}).SetRollingWindow(key, per, val, pipeline)
}

func (n Native) GetRollingWindow(key string, per int64, pipeline bool) (int, []interface{}) {
	return (&rate{db: simple.rate}).GetRollingWindow(key, per, pipeline)
}

func (n Native) GetKey(key string) (string, error) {
	return (&kv{Options: n.Options, db: simple.general}).GetKey(key)
}
func (n Native) GetMultiKey(keys []string) ([]string, error) {
	return (&kv{Options: n.Options, db: simple.general}).GetMultiKey(keys)
}
func (n Native) GetRawKey(key string) (string, error) {
	return (&kv{Options: n.Options, db: simple.general}).GetRawKey(key)
}

func (n Native) SetKey(key string, session string, timeout int64) error {
	return (&kv{Options: n.Options, db: simple.general}).SetKey(key, session, timeout)
}

func (n Native) SetRawKey(key string, session string, timeout int64) error {
	return (&kv{Options: n.Options, db: simple.general}).SetRawKey(key, session, timeout)
}

func (n Native) GetKeys(filter string) []string {
	return (&kv{Options: n.Options, db: simple.general}).GetKeys(filter)
}

func (n Native) DeleteKey(filter string) bool {
	return (&kv{Options: n.Options, db: simple.general}).DeleteKey(filter)
}

func (n Native) DeleteAllKeys() bool {
	return (&kv{Options: n.Options, db: simple.general}).DeleteAllKeys()
}

func (n Native) DeleteRawKey(key string) bool {
	return (&kv{Options: n.Options, db: simple.general}).DeleteRawKey(key)
}
func (n Native) GetKeysAndValues() map[string]string {
	return (&kv{Options: n.Options, db: simple.general}).GetKeysAndValues()
}
func (n Native) GetKeysAndValuesWithFilter(filter string) map[string]string {
	return (&kv{Options: n.Options, db: simple.general}).GetKeysAndValuesWithFilter(filter)
}
func (n Native) DeleteKeys(keys []string) bool {
	return (&kv{Options: n.Options, db: simple.general}).DeleteKeys(keys)
}
func (n Native) Decrement(key string) {
	(&kv{Options: n.Options, db: simple.general}).Decrement(key)
}
func (n Native) IncrememntWithExpire(key string, expire int64) int64 {
	return (&kv{Options: n.Options, db: simple.general}).IncrememntWithExpire(key, expire)
}

func (n Native) DeleteScanMatch(filter string) bool {
	return (&kv{Options: n.Options, db: simple.general}).DeleteScanMatch(filter)
}

func (n Native) GetKeyPrefix() string {
	return n.KeyPrefix
}

func (n Native) Exists(key string) (bool, error) {
	return (&kv{Options: n.Options, db: simple.general}).Exists(key)
}

func (n Native) GetKeyTTL(key string) (ttl int64, err error) {
	return (&kv{Options: n.Options, db: simple.general}).GetKeyTTL(key)
}

func (n Native) AddToSet(key string, value string) {
	(&nativeRedis{Options: n.Options, db: simple.general}).AddToSet(key, value)
}

func (n Native) GetSet(key string) (map[string]string, error) {
	return (&nativeRedis{Options: n.Options, db: simple.general}).GetSet(key)
}

func (n Native) AddToSortedSet(key string, value string, score float64) {
	(&nativeRedis{Options: n.Options, db: simple.general}).AddToSortedSet(key, value, score)
}

func (n Native) RemoveFromSet(key string, value string) {
	(&nativeRedis{Options: n.Options, db: simple.general}).RemoveFromSet(key, value)
}

func (n Native) GetSortedSetRange(key string, from string, to string) ([]string, []float64, error) {
	return (&nativeRedis{Options: n.Options, db: simple.general}).GetSortedSetRange(key, from, to)
}

func (n Native) RemoveSortedSetRange(key string, from string, to string) error {
	return (&nativeRedis{Options: n.Options, db: simple.general}).RemoveSortedSetRange(key, from, to)
}

func (n Native) GetListRange(key string, from int64, to int64) ([]string, error) {
	return (&nativeRedis{Options: n.Options, db: simple.general}).GetListRange(key, from, to)
}

func (n Native) RemoveFromList(key string, value string) error {
	return (&nativeRedis{Options: n.Options, db: simple.general}).RemoveFromList(key, value)
}

func (n Native) AppendToSet(key string, value string) {
	(&nativeRedis{Options: n.Options, db: simple.general}).AppendToSet(key, value)
}

func (n Native) Publish(channel, message string) error {
	return (&nativeNotify{client: simple.pubsub}).Publish(channel, message)
}

func (n Native) StartPubSubHandler(channel string, callback func(interface{})) error {
	return (&nativeNotify{client: simple.pubsub}).StartPubSubHandler(channel, callback)
}

func (n Native) AppendToSetPipelined(key string, records [][]byte) {
	(&nativeAnalytics{client: simple.analytics}).AppendToSetPipelined(key, records)
}

func (n Native) GetAndDeleteSet(string) []interface{} { return nil }
func (n Native) SetExp(string, int64) error           { return nil }
func (n Native) GetExp(string) (int64, error)         { return 0, nil }

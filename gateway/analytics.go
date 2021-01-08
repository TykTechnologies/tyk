package gateway

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TykTechnologies/tyk/regexp"
	maxminddb "github.com/oschwald/maxminddb-golang"
	"google.golang.org/protobuf/proto"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
	pb "github.com/TykTechnologies/tyk-pump/analyticspb"
	"google.golang.org/grpc"
)


const analyticsKeyName = "tyk-system-analytics"

const (
	recordsBufferFlushInterval       = 200 * time.Millisecond
	recordsBufferForcedFlushInterval = 1 * time.Second
)

func initNormalisationPatterns() (pats config.NormaliseURLPatterns) {
	pats.UUIDs = regexp.MustCompile(`[0-9a-fA-F]{8}(-)?[0-9a-fA-F]{4}(-)?[0-9a-fA-F]{4}(-)?[0-9a-fA-F]{4}(-)?[0-9a-fA-F]{12}`)
	pats.IDs = regexp.MustCompile(`\/(\d+)`)

	for _, pattern := range config.Global().AnalyticsConfig.NormaliseUrls.Custom {
		if patRe, err := regexp.Compile(pattern); err != nil {
			log.Error("failed to compile custom pattern: ", err)
		} else {
			pats.Custom = append(pats.Custom, patRe)
		}
	}
	return
}

type AnalyticsHandler interface{
	Init(globalConf config.Config)
	Stop()
	RecordHit(record *pb.AnalyticsRecord) error
	GetStore() storage.AnalyticsHandler
	SetStore(storage.AnalyticsHandler)
	GetGeoIPDB() *maxminddb.Reader
}


// RedisAnalyticsHandler will record analytics data to a redis back end
// as defined in the Config object
type RedisAnalyticsHandler struct {
	Store            storage.AnalyticsHandler
	GeoIPDB          *maxminddb.Reader
	globalConf       config.Config
	recordsChan      chan *pb.AnalyticsRecord
	workerBufferSize uint64
	shouldStop       uint32
	poolWg           sync.WaitGroup
}

func (r *RedisAnalyticsHandler) Init(globalConf config.Config) {
	r.globalConf = globalConf

	if r.globalConf.AnalyticsConfig.EnableGeoIP {
		if db, err := maxminddb.Open(r.globalConf.AnalyticsConfig.GeoIPDBLocation); err != nil {
			log.Error("Failed to init GeoIP Database: ", err)
		} else {
			r.GeoIPDB = db
		}
	}

	analytics.GetStore().Connect()

	ps := config.Global().AnalyticsConfig.PoolSize
	recordsBufferSize := config.Global().AnalyticsConfig.RecordsBufferSize
	r.workerBufferSize = recordsBufferSize / uint64(ps)
	log.WithField("workerBufferSize", r.workerBufferSize).Debug("Analytics pool worker buffer size")

	r.recordsChan = make(chan *pb.AnalyticsRecord, recordsBufferSize)

	// start worker pool
	atomic.SwapUint32(&r.shouldStop, 0)
	for i := 0; i < ps; i++ {
		r.poolWg.Add(1)
		go r.recordWorker()
	}
}

func (r *RedisAnalyticsHandler) Stop() {
	// flag to stop sending records into channel
	atomic.SwapUint32(&r.shouldStop, 1)

	// close channel to stop workers
	close(r.recordsChan)

	// wait for all workers to be done
	r.poolWg.Wait()
}

// RecordHit will store an AnalyticsRecord in Redis
func (r *RedisAnalyticsHandler) RecordHit(record *pb.AnalyticsRecord) error {
	// check if we should stop sending records 1st
	if atomic.LoadUint32(&r.shouldStop) > 0 {
		return nil
	}

	// just send record to channel consumed by pool of workers
	// leave all data crunching and Redis I/O work for pool workers
	r.recordsChan <- record

	return nil
}

func (r *RedisAnalyticsHandler) recordWorker() {
	defer r.poolWg.Done()

	// this is buffer to send one pipelined command to redis
	// use r.recordsBufferSize as cap to reduce slice re-allocations
	recordsBuffer := make([][]byte, 0, r.workerBufferSize)

	// read records from channel and process
	lastSentTs := time.Now()
	for {
		readyToSend := false
		select {

		case record, ok := <-r.recordsChan:
			// check if channel was closed and it is time to exit from worker
			if !ok {
				// send what is left in buffer
				r.Store.AppendToSetPipelined(analyticsKeyName, recordsBuffer)
				return
			}

			// we have new record - prepare it and add to buffer

			// If we are obfuscating API Keys, store the hashed representation (config check handled in hashing function)
			record.APIKey = storage.HashKey(record.APIKey)

			if r.globalConf.SlaveOptions.UseRPC {
				// Extend tag list to include this data so wecan segment by node if necessary
				record.Tags = append(record.Tags, "tyk-hybrid-rpc")
			}

			if r.globalConf.DBAppConfOptions.NodeIsSegmented {
				// Extend tag list to include this data so we can segment by node if necessary
				record.Tags = append(record.Tags, r.globalConf.DBAppConfOptions.Tags...)
			}

			// Lets add some metadata
			if record.APIKey != "" {
				record.Tags = append(record.Tags, "key-"+record.APIKey)
			}

			if record.OrgID != "" {
				record.Tags = append(record.Tags, "org-"+record.OrgID)
			}

			record.Tags = append(record.Tags, "api-"+record.APIID)

			// fix paths in record as they might have omitted leading "/"
			if !strings.HasPrefix(record.Path, "/") {
				record.Path = "/" + record.Path
			}
			if !strings.HasPrefix(record.RawPath, "/") {
				record.RawPath = "/" + record.RawPath
			}

			if encoded, err := proto.Marshal(record); err != nil {
				log.WithError(err).Error("Error encoding analytics data")
			} else {
				recordsBuffer = append(recordsBuffer, encoded)
			}

			// identify that buffer is ready to be sent
			readyToSend = uint64(len(recordsBuffer)) == r.workerBufferSize

		case <-time.After(recordsBufferFlushInterval):
			// nothing was received for that period of time
			// anyways send whatever we have, don't hold data too long in buffer
			readyToSend = true
		}

		// send data to Redis and reset buffer
		if len(recordsBuffer) > 0 && (readyToSend || time.Since(lastSentTs) >= recordsBufferForcedFlushInterval) {
			r.Store.AppendToSetPipelined(analyticsKeyName, recordsBuffer)
			recordsBuffer = recordsBuffer[:0]
			lastSentTs = time.Now()
		}
	}
}

func (r *RedisAnalyticsHandler) GetStore() storage.AnalyticsHandler{
	return r.Store
}
func (r *RedisAnalyticsHandler) SetStore(store storage.AnalyticsHandler) {
	 r.Store = store
}

func (r *RedisAnalyticsHandler) GetGeoIPDB() *maxminddb.Reader{
	return r.GeoIPDB
}

func DurationToMillisecond(d time.Duration) float64 {
	return float64(d) / 1e6
}

type GrpcAnalyticsHandler struct{
	conn *grpc.ClientConn

	client pb.AnalyticsServiceClient
	GeoIPDB          *maxminddb.Reader
	globalConf       config.Config
	recordsChan      chan *pb.AnalyticsRecord
	shouldStop       uint32
	poolWg           sync.WaitGroup
	workerBufferSize uint64

	stopChan	chan bool

}

func (g *GrpcAnalyticsHandler)  Init(globalConf config.Config){
	g.globalConf = globalConf

	if g.globalConf.AnalyticsConfig.EnableGeoIP {
		if db, err := maxminddb.Open(g.globalConf.AnalyticsConfig.GeoIPDBLocation); err != nil {
			log.Error("Failed to init GeoIP Database: ", err)
		} else {
			g.GeoIPDB = db
		}
	}

	g.initConn()

	ps := config.Global().AnalyticsConfig.PoolSize
	recordsBufferSize := config.Global().AnalyticsConfig.RecordsBufferSize
	g.workerBufferSize = recordsBufferSize / uint64(ps)
	log.WithField("workerBufferSize", g.workerBufferSize).Debug("Analytics pool worker buffer size")

	g.recordsChan = make(chan *pb.AnalyticsRecord, recordsBufferSize)
	g.stopChan = make(chan bool, recordsBufferSize)

	// start worker pool
	atomic.SwapUint32(&g.shouldStop, 0)
	for i := 0; i < ps; i++ {
		g.poolWg.Add(1)
		go g.recordWorker()
	}
}
func (g *GrpcAnalyticsHandler) Stop(){
	defer g.conn.Close()
	// flag to stop sending records into channel
	atomic.SwapUint32(&g.shouldStop, 1)

	recordsBufferSize := config.Global().AnalyticsConfig.RecordsBufferSize
	var i uint64
	for i = 0; i < recordsBufferSize; i++ {
		g.stopChan <- true
	}

	// close channel to stop workers
	close(g.recordsChan)
	close(g.stopChan)
	// wait for all workers to be done
	g.poolWg.Wait()
}

func (g *GrpcAnalyticsHandler) RecordHit(record *pb.AnalyticsRecord) error{
	// check if we should stop sending records 1st
	if atomic.LoadUint32(&g.shouldStop) > 0 {
		return nil
	}

	// just send record to channel consumed by pool of workers
	// leave all data crunching and Redis I/O work for pool workers
	g.recordsChan <- record

	return nil
}

func (g *GrpcAnalyticsHandler) recordWorker(){
	defer g.poolWg.Done()

	stream, err := g.client.SendData(context.Background())
	if err != nil {
		log.WithError(err).Error("Error while calling SendData gRPC: %v", err)
	}
	for {
		select {
		case record:= <-g.recordsChan:
			stream.Send(record)
			if err != nil {
				log.Fatalf("Error sending data to Pump gRPC: %v",err)
			}
			log.Info("Sent analytic record to pump via gRPC!")
		case <- g.stopChan:
			_, err := stream.CloseAndRecv()
			if err != nil {
				log.Fatalf("Error while closing and receiving SendData gRPC: %v", err)
			}
		}
	}
}

func (g *GrpcAnalyticsHandler) GetStore() storage.AnalyticsHandler{
	return nil
}
func (g *GrpcAnalyticsHandler) SetStore(storage.AnalyticsHandler){
}
func (g *GrpcAnalyticsHandler) GetGeoIPDB() *maxminddb.Reader{
	return g.GeoIPDB
}

func (g *GrpcAnalyticsHandler) initConn(){
	log.Info("Connecting to gRPC!!")
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Could not connect: %v",err)
	}
	g.conn = conn
	g.client = pb.NewAnalyticsServiceClient(conn)
}
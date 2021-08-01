package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/TykTechnologies/tyk/api"
	"github.com/TykTechnologies/tyk/gateway"
	"google.golang.org/grpc"
	"gopkg.in/vmihailenco/msgpack.v2"
)

func main() {
	port := flag.Int("port", 8900, "listening port")
	ls, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatal("Failed to start listener", err)
	}
	defer ls.Close()
	svr := grpc.NewServer()
	api.RegisterAnalyticsSyncServer(svr, server{})
	log.Println("Listening on ", ls.Addr())
	if err := svr.Serve(ls); err != nil {
		log.Fatal("exited  grpc server", err)
	}
}

var _ api.AnalyticsSyncServer = (*server)(nil)

type server struct {
	api.UnimplementedAnalyticsSyncServer
}

func (server) Sync(sink api.AnalyticsSync_SyncServer) error {
	for {
		data, err := sink.Recv()
		if err != nil {
			return err
		}
		access(data.Data)
	}
}

var out = json.NewEncoder(os.Stdout)

func access(data [][]byte) {
	var r gateway.AnalyticsRecord
	for _, b := range data {
		if err := msgpack.Unmarshal(b, &r); err != nil {
			continue
		}
		out.Encode(map[string]string{
			"time":   r.TimeStamp.Format(time.RFC3339Nano),
			"host":   r.Host,
			"method": r.Method,
			"path":   r.RawPath,
			"status": strconv.Itoa(r.ResponseCode),
		})
	}
}

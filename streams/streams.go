package streams

import (
	// Import all standard Benthos components
	"context"
	"os"

	_ "github.com/benthosdev/benthos/v4/public/components/all"
	"github.com/benthosdev/benthos/v4/public/service"
)

type Server struct {
	stopFunc context.CancelFunc
}

func New() *Server {
	return &Server{}
}

func (s *Server) Start() {
	os.Args = []string{"benthos", "-c", "streams/config.yaml", "streams"}
	ctx, stopFunc := context.WithCancel(context.Background())
	s.stopFunc = stopFunc
	go service.RunCLI(ctx)
}

func (s *Server) Stop() {
	s.stopFunc()
}

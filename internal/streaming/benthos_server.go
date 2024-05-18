package streaming

import (
	// Import all standard Benthos components
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	_ "github.com/benthosdev/benthos/v4/public/components/all"
	"github.com/benthosdev/benthos/v4/public/service"
	"gopkg.in/yaml.v2"
)

func generateRandomPassword() string {
	b := make([]byte, 16) // 128 bit, adjust length as needed
	if _, err := rand.Read(b); err != nil {
		panic(err) // Handle error appropriately for your use case
	}
	return hex.EncodeToString(b)
}

func hashPassword(password string) string {
	hasher := sha256.New()
	hasher.Write([]byte(password))
	return base64.StdEncoding.EncodeToString(hasher.Sum(nil))
}

type Server struct {
	stopFunc context.CancelFunc
	client   *Client
}

var once sync.Once
var serverSingleton *Server

func New() *Server {
	once.Do(func() {
		serverSingleton = &Server{}
	})
	return serverSingleton
}

func (s *Server) Start() error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err) // Handle error appropriately for your use case
	}
	port := listener.Addr().(*net.TCPAddr).Port
	// Close the listener so the port is free again.
	listener.Close()

	password := generateRandomPassword()
	passwordHash := hashPassword(password)

	configContent := fmt.Sprintf(`http:
  address: "127.0.0.1:%d"
  enabled: true
  root_path: /benthos
  debug_endpoints: false
  basic_auth:
    enabled: true
    username: "tyk"
    password_hash: "%s"
    algorithm: "sha256"
    salt: ""`, port, passwordHash)

	tempFile, err := os.CreateTemp("", "benthos_config_*.yaml")
	if err != nil {
		panic(err) // Handle error appropriately for your use case
	}
	defer tempFile.Close()

	_, err = tempFile.WriteString(configContent)
	if err != nil {
		panic(err) // Handle error appropriately for your use case
	}

	os.Args = []string{"benthos", "-c", tempFile.Name(), "streams"}
	ctx, stopFunc := context.WithCancel(context.Background())
	s.stopFunc = stopFunc
	go service.RunCLI(ctx)

	s.client = NewClient(fmt.Sprintf("http://localhost:%d/benthos", port), "tyk", password)

	return s.WaitForReady()
}

func (s *Server) Stop() {
	s.stopFunc()
}

func (s *Server) WaitForReady() error {
	t := 0
	for {
		time.Sleep(500 * time.Millisecond)
		_, err := s.client.GetReady()
		if err == nil {
			break
		}
		t += 1

		if t == 4 {
			return fmt.Errorf("Benthos: failed to get ready status from streams server")
		}
	}

	log.Println("Benthos: streaming server started and ready")
	return nil
}

func (s *Server) AddStream(streamID string, config map[string]interface{}) error {
	configPayload, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	// First, try to find the existing stream by given ID
	_, err = s.client.GetStream(streamID)
	if err != nil {
		// If the stream does not exist, create a new one
		result, err := s.client.CreateStream(streamID, configPayload)
		if err != nil {
			return err
		}
		fmt.Printf("Stream created: %+v\n", result)
	} else {
		result, err := s.client.UpdateStream(streamID, configPayload)
		if err != nil {
			return err
		}
		fmt.Printf("Stream updated: %+v\n", result)
	}
	return nil
}

func (s *Server) RemoveStream(streamID string) error {
	_, err := s.client.GetStream(streamID)
	if err != nil {
		// Assuming err means stream does not exist, hence return nil error
		return nil
	}
	result, err := s.client.DeleteStream(streamID)
	if err != nil {
		return err
	}
	fmt.Printf("Stream removed: %+v\n", result)
	return nil
}

func (s *Server) Streams() (map[string]interface{}, error) {
	result, err := s.client.GetStreams()
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Server) Reset() error {
	streams, err := s.Streams()
	if err != nil {
		return err
	}

	for streamID := range streams {
		err := s.RemoveStream(streamID)
		if err != nil {
			return err
		}
	}

	return nil
}

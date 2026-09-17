// tyk-kafka-ack-worker is a minimal downstream HTTP application for Tyk
// Streams external Kafka acknowledgments. It is an example, not a database.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

type journal struct {
	mu   sync.Mutex
	path string
	seen map[string]struct{}
}

func openJournal(path string) (*journal, error) {
	j := &journal{path: path, seen: map[string]struct{}{}}
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line != "" {
			j.seen[line] = struct{}{}
		}
	}
	return j, nil
}

// apply records completion durably before the Kafka acknowledgment is sent.
// Replace this journal with the same database transaction as the real business
// mutation in production.
func (j *journal) apply(id string, _ []byte) (bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, ok := j.seen[id]; ok {
		return false, nil
	}
	f, err := os.OpenFile(j.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return false, err
	}
	if _, err = fmt.Fprintln(f, id); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return false, err
	}
	j.seen[id] = struct{}{}
	return true, nil
}

type worker struct {
	ackURL, authorization string
	client                *http.Client
	journal               *journal
	attempts              int
}

func (w *worker) acknowledge(ctx context.Context, token string) error {
	body, _ := json.Marshal(map[string][]string{"tokens": {token}})
	var last error
	for attempt := 0; attempt < w.attempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.ackURL, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		if w.authorization != "" {
			req.Header.Set("Authorization", w.authorization)
		}
		resp, err := w.client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted {
				return nil
			}
			err = fmt.Errorf("acknowledgment returned %s", resp.Status)
		}
		last = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(1<<attempt) * 100 * time.Millisecond):
		}
	}
	return last
}

func (w *worker) process(rw http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	eventID, token := r.Header.Get("Tyk-Kafka-Message-ID"), r.Header.Get("Tyk-Kafka-Ack-Token")
	if eventID == "" || token == "" {
		http.Error(rw, "missing Tyk Kafka delivery headers", http.StatusBadRequest)
		return
	}
	payload, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(rw, "read request", http.StatusBadRequest)
		return
	}
	if _, err = w.journal.apply(eventID, payload); err != nil {
		http.Error(rw, "business transaction failed", http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err = w.acknowledge(ctx, token); err != nil {
		// The business result is durable. A non-2xx asks Tyk/Bento to retry the
		// delivery; the journal makes that expected duplicate harmless.
		http.Error(rw, "acknowledgment unavailable", http.StatusServiceUnavailable)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}

func main() {
	ackURL := os.Getenv("TYK_KAFKA_ACK_URL")
	if ackURL == "" {
		log.Fatal("TYK_KAFKA_ACK_URL is required")
	}
	path := os.Getenv("WORKER_JOURNAL")
	if path == "" {
		path = "ack-worker.journal"
	}
	j, err := openJournal(path)
	if err != nil {
		log.Fatal(err)
	}
	w := &worker{ackURL: ackURL, authorization: os.Getenv("TYK_AUTHORIZATION"), client: &http.Client{Timeout: 5 * time.Second}, journal: j, attempts: 5}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /process", w.process)
	address := os.Getenv("LISTEN_ADDR")
	if address == "" {
		address = ":8081"
	}
	server := &http.Server{Addr: address, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Printf("external-ack worker listening on %s", address)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/TykTechnologies/gorpc"
	"github.com/TykTechnologies/tyk/internal/model"
)

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	log.Println("Starting Mock MDCB RPC Server...")

	// Create dispatcher and register handler functions
	dispatcher := gorpc.NewDispatcher()

	// GetApiDefinitions - return empty list so gateways use their local APIs
	dispatcher.AddFunc("GetApiDefinitions", func(clientAddr string, dr *model.DefRequest) (string, error) {
		log.Printf("[RPC] GetApiDefinitions called from: %s", clientAddr)
		return "[]", nil
	})

	// GetPolicies - return empty list
	dispatcher.AddFunc("GetPolicies", func(clientAddr string, orgid string) (string, error) {
		log.Printf("[RPC] GetPolicies called for OrgID: %s from: %s", orgid, clientAddr)
		return "[]", nil
	})

	// Login - always allow login
	dispatcher.AddFunc("Login", func(clientAddr, userKey string) bool {
		log.Printf("[RPC] Login called from: %s with key: %s", clientAddr, userKey)
		return true
	})

	// GetKey - return error so gateway uses local storage
	dispatcher.AddFunc("GetKey", func(clientAddr, key string) (string, error) {
		log.Printf("[RPC] GetKey called for key: %s from: %s", key, clientAddr)
		return "", nil
	})

	// Ping - health check
	dispatcher.AddFunc("Ping", func() bool {
		return true
	})

	// PurgeCache - acknowledge cache purge
	dispatcher.AddFunc("PurgeCache", func() bool {
		log.Printf("[RPC] PurgeCache called")
		return true
	})

	// Create and start TCP server on port 9090
	addr := "0.0.0.0:9090"
	server := gorpc.NewTCPServer(addr, dispatcher.NewHandlerFunc())
	server.LogError = gorpc.NilErrorLogger

	// Start server
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server on %s: %v", addr, err)
	}

	log.Printf("✓ Mock MDCB RPC Server listening on %s", addr)
	log.Println("✓ Data plane gateways can now connect and sync APIs")
	log.Println("✓ Press Ctrl+C to stop")

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("\nShutting down Mock MDCB RPC Server...")
	server.Stop()
}

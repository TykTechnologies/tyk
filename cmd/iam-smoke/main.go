// Command iam-smoke is a throwaway Layer-3 smoke test for GCP Memorystore IAM
// auth. Run it on a GCE VM (with an attached service account granted
// roles/memorystore.dbConnectionUser) inside the instance's VPC. It connects to
// Memorystore for Valkey using our GCP credentials provider over TLS and does
// PING + SET + GET. Success proves Google's server accepts our minted token.
//
//	./iam-smoke -addr <PRIVATE_IP>:6379
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/TykTechnologies/storage/iamauth"
	"github.com/TykTechnologies/storage/temporal/connector"
	keyvalue "github.com/TykTechnologies/storage/temporal/keyvalue"
	"github.com/TykTechnologies/storage/temporal/model"
)

func main() {
	addr := flag.String("addr", "", "Memorystore Valkey host:port (private IP)")
	serviceAccount := flag.String("sa", "", "optional service account to impersonate")
	insecureTLS := flag.Bool("insecure-tls", true, "skip TLS verification (smoke test only)")
	cluster := flag.Bool("cluster", false, "set for Redis Cluster / Valkey cluster mode")
	flag.Parse()

	if *addr == "" {
		log.Fatal("-addr is required (Memorystore private IP, e.g. 10.0.0.3:6379)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	provider, err := iamauth.NewProvider(ctx, iamauth.Config{
		Provider:       iamauth.ProviderGCP,
		ServiceAccount: *serviceAccount,
	})
	if err != nil {
		log.Fatalf("FAIL: building GCP credentials provider: %v", err)
	}
	log.Println("OK: GCP credentials provider built (ADC token path)")

	conn, err := connector.NewConnector(model.RedisV9Type,
		model.WithRedisConfig(&model.RedisOptions{
			Addrs:         []string{*addr},
			EnableCluster: *cluster,
			Timeout:       10,
		}),
		model.WithTLS(&model.TLS{Enable: true, InsecureSkipVerify: *insecureTLS}),
		model.WithCredentialsProvider(provider),
	)
	if err != nil {
		log.Fatalf("FAIL: building connector: %v", err)
	}

	if err := conn.Ping(ctx); err != nil {
		log.Fatalf("FAIL: PING (token rejected by server or unreachable): %v", err)
	}
	log.Println("OK: PING succeeded — Memorystore accepted the IAM token")

	kv, err := keyvalue.NewKeyValue(conn)
	if err != nil {
		log.Fatalf("FAIL: keyvalue: %v", err)
	}

	const key, want = "tyk:iam:smoke", "it-works"
	if err := kv.Set(ctx, key, want, 60*time.Second); err != nil {
		log.Fatalf("FAIL: SET: %v", err)
	}
	got, err := kv.Get(ctx, key)
	if err != nil {
		log.Fatalf("FAIL: GET: %v", err)
	}
	if got != want {
		log.Fatalf("FAIL: GET returned %q, want %q", got, want)
	}

	fmt.Println("OK: SET/GET round-trip succeeded")
	fmt.Println("PASS: GCP Memorystore IAM auth works end-to-end")
}

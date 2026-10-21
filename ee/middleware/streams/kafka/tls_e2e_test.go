package kafka

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/IBM/sarama"
	containerapi "github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	_ "github.com/warpstreamlabs/bento/public/components/all"
	"github.com/warpstreamlabs/bento/public/service"
)

type kafkaTLSMaterial struct{ ca, serverCert, serverKey, clientCert, clientKey, rogueCA string }

func TestExternalAcknowledgmentKafkaTLSE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	material := generateKafkaTLSMaterial(t)
	for _, tc := range []struct {
		name       string
		clientAuth bool
	}{{"TLS", false}, {"mTLS", true}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			container, brokers, err := startKafkaTLSContainer(t, ctx, material, tc.clientAuth)
			require.NoError(t, err)
			t.Cleanup(func() {
				cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
				defer stop()
				require.NoError(t, container.Terminate(cleanup))
			})
			topic := runExternalAckTLSCase(t, ctx, brokers, material, tc.clientAuth)
			assertTLSConnectorRejected(t, ctx, brokers, topic, material, tc.clientAuth, true)
			if tc.clientAuth {
				assertTLSConnectorRejected(t, ctx, brokers, topic, material, false, false)
			}
		})
	}
}

func startKafkaTLSContainer(t *testing.T, ctx context.Context, material kafkaTLSMaterial, clientAuth bool) (testcontainers.Container, []string, error) {
	t.Helper()
	secrets := t.TempDir()
	for name, content := range map[string]string{"server.pem": material.serverCert, "server.key": material.serverKey, "ca.pem": material.ca, "keystore_creds": "changeit", "key_creds": "changeit", "truststore_creds": "changeit"} {
		if err := os.WriteFile(filepath.Join(secrets, name), []byte(content), 0o600); err != nil {
			return nil, nil, err
		}
	}
	toolCtx, toolCancel := context.WithTimeout(ctx, 20*time.Second)
	defer toolCancel()
	if output, err := exec.CommandContext(toolCtx, "openssl", "pkcs12", "-export", "-in", filepath.Join(secrets, "server.pem"), "-inkey", filepath.Join(secrets, "server.key"), "-certfile", filepath.Join(secrets, "ca.pem"), "-out", filepath.Join(secrets, "kafka.keystore.p12"), "-name", "kafka", "-passout", "pass:changeit").CombinedOutput(); err != nil {
		return nil, nil, fmt.Errorf("create PKCS12 keystore: %w: %s", err, output)
	}
	if output, err := exec.CommandContext(toolCtx, "keytool", "-importcert", "-noprompt", "-alias", "ca", "-file", filepath.Join(secrets, "ca.pem"), "-keystore", filepath.Join(secrets, "kafka.truststore.p12"), "-storetype", "PKCS12", "-storepass", "changeit").CombinedOutput(); err != nil {
		return nil, nil, fmt.Errorf("create PKCS12 truststore: %w: %s", err, output)
	}
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	hostPort := reservation.Addr().(*net.TCPAddr).Port
	_ = reservation.Close()
	sslPort := nat.Port("9095/tcp")
	req := testcontainers.ContainerRequest{
		Image: "confluentinc/confluent-local:7.5.0", ExposedPorts: []string{string(sslPort)},
		Env: map[string]string{
			"CLUSTER_ID": "MkU3OEVBNTcwNTJENDM2Qk", "KAFKA_NODE_ID": "1", "KAFKA_BROKER_ID": "1", "KAFKA_PROCESS_ROLES": "broker,controller",
			"KAFKA_LISTENERS":                      "SSL://0.0.0.0:9095,BROKER://0.0.0.0:9092,CONTROLLER://0.0.0.0:9094",
			"KAFKA_ADVERTISED_LISTENERS":           fmt.Sprintf("SSL://localhost:%d,BROKER://localhost:9092", hostPort),
			"KAFKA_LISTENER_SECURITY_PROTOCOL_MAP": "SSL:SSL,BROKER:PLAINTEXT,CONTROLLER:PLAINTEXT", "KAFKA_INTER_BROKER_LISTENER_NAME": "BROKER", "KAFKA_CONTROLLER_LISTENER_NAMES": "CONTROLLER", "KAFKA_CONTROLLER_QUORUM_VOTERS": "1@localhost:9094",
			"KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR": "1", "KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR": "1", "KAFKA_TRANSACTION_STATE_LOG_MIN_ISR": "1", "KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS": "0",
			"KAFKA_SSL_KEYSTORE_TYPE": "PKCS12", "KAFKA_SSL_KEYSTORE_FILENAME": "kafka.keystore.p12", "KAFKA_SSL_KEYSTORE_CREDENTIALS": "keystore_creds", "KAFKA_SSL_KEY_CREDENTIALS": "key_creds",
			"KAFKA_SSL_TRUSTSTORE_TYPE": "PKCS12", "KAFKA_SSL_TRUSTSTORE_FILENAME": "kafka.truststore.p12", "KAFKA_SSL_TRUSTSTORE_CREDENTIALS": "truststore_creds", "KAFKA_SSL_CLIENT_AUTH": map[bool]string{false: "none", true: "required"}[clientAuth],
		},
		WaitingFor: wait.ForLog("Transitioning from RECOVERY to RUNNING").WithStartupTimeout(75 * time.Second),
		HostConfigModifier: func(hc *containerapi.HostConfig) {
			hc.PortBindings = nat.PortMap{sslPort: {{HostIP: "127.0.0.1", HostPort: fmt.Sprint(hostPort)}}}
		},
		Mounts: testcontainers.ContainerMounts{testcontainers.BindMount(secrets, testcontainers.ContainerMountTarget("/etc/kafka/secrets"))},
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
	if err != nil {
		return c, nil, err
	}
	return c, []string{fmt.Sprintf("localhost:%d", hostPort)}, nil
}

func runExternalAckTLSCase(t *testing.T, ctx context.Context, brokers []string, m kafkaTLSMaterial, clientAuth bool) string {
	t.Helper()
	topic := fmt.Sprintf("tls-ack-%d", time.Now().UnixNano())
	group := topic + "-group"
	component := topic + "-component"
	clientCert, err := tls.X509KeyPair([]byte(m.clientCert), []byte(m.clientKey))
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM([]byte(m.ca)))
	cfg := sarama.NewConfig()
	cfg.Version = sarama.V2_8_0_0
	cfg.Producer.Return.Successes = true
	cfg.Net.TLS.Enable = true
	cfg.Net.TLS.Config = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{clientCert}, ServerName: "localhost"}
	cfg.Net.DialTimeout = 5 * time.Second
	cfg.Net.ReadTimeout = 5 * time.Second
	cfg.Net.WriteTimeout = 5 * time.Second
	producer, err := sarama.NewSyncProducer(brokers, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { boundedSecurityClose(t, "TLS producer", producer.Close) })
	_, _, err = producer.SendMessage(&sarama.ProducerMessage{Topic: topic, Value: sarama.StringEncoder("tls-event")})
	require.NoError(t, err)
	var mu sync.Mutex
	token, body := "", ""
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		token = r.Header.Get("Tyk-Kafka-Ack-Token")
		body = string(b)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(downstream.Close)
	provider, err := NewSharedAckSigningKeyProvider("tls-v1", map[string][]byte{"tls-v1": []byte("tls-external-ack-signing-secret-32")})
	require.NoError(t, err)
	require.NoError(t, GlobalRuntimeAckKeyRegistry.Configure(component, provider))
	t.Cleanup(func() { GlobalRuntimeAckKeyRegistry.Remove(component) })
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	certPath := filepath.Join(dir, "client.pem")
	keyPath := filepath.Join(dir, "client.key")
	require.NoError(t, os.WriteFile(caPath, []byte(m.ca), 0600))
	require.NoError(t, os.WriteFile(certPath, []byte(m.clientCert), 0600))
	require.NoError(t, os.WriteFile(keyPath, []byte(m.clientKey), 0600))
	clientBlock := ""
	if clientAuth {
		clientBlock = fmt.Sprintf("\n      client_certs:\n        - cert_file: %q\n          key_file: %q", certPath, keyPath)
	}
	builder := service.NewStreamBuilder()
	require.NoError(t, builder.SetYAML(fmt.Sprintf(`input:
  tyk_kafka:
    seed_brokers: [%q]
    topics: [%q]
    consumer_group: %q
    tls:
      enabled: true
      root_cas_file: %q%s
    acknowledgment:
      mode: external_ack
      component_id: %q
      checkpoint_limit: 1
      max_in_flight: 1
      max_in_flight_bytes: 1MiB
      routing: local
output:
  http_client:
    url: %q
    verb: POST
    headers:
      Tyk-Kafka-Ack-Token: '${! @tyk_kafka_ack_token }'
`, brokers[0], topic, group, caPath, clientBlock, component, downstream.URL)))
	stream, err := builder.Build()
	require.NoError(t, err)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = stream.Run(runCtx) }()
	t.Cleanup(func() {
		c, x := context.WithTimeout(context.Background(), 10*time.Second)
		defer x()
		_ = stream.Stop(c)
	})
	require.Eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return token != "" && body == "tls-event" }, 30*time.Second, 100*time.Millisecond)
	client, err := sarama.NewClient(brokers, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { boundedSecurityClose(t, "TLS observer", client.Close) })
	mu.Lock()
	ackToken := token
	mu.Unlock()
	h := NewAcknowledgmentHandler(GlobalControllerRegistry, ControllerKey{APIID: "runtime", StreamID: "runtime", ComponentID: component}, HandlerLimits{})
	req := httptest.NewRequest(http.MethodPost, "/ack", bytes.NewBufferString(fmt.Sprintf(`{"tokens":[%q]}`, ackToken)))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.Eventually(t, func() bool { return fetchCommittedOffset(t, client, group, topic, 0) == 1 }, 10*time.Second, 100*time.Millisecond)
	return topic
}

func assertTLSConnectorRejected(t *testing.T, ctx context.Context, brokers []string, topic string, m kafkaTLSMaterial, includeClient, rogue bool) {
	t.Helper()
	dir := t.TempDir()
	ca := m.ca
	if rogue {
		ca = m.rogueCA
	}
	caPath := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(caPath, []byte(ca), 0600))
	client := ""
	if includeClient {
		cp, kp := filepath.Join(dir, "c.pem"), filepath.Join(dir, "c.key")
		require.NoError(t, os.WriteFile(cp, []byte(m.clientCert), 0600))
		require.NoError(t, os.WriteFile(kp, []byte(m.clientKey), 0600))
		client = fmt.Sprintf("\n      client_certs:\n        - cert_file: %q\n          key_file: %q", cp, kp)
	}
	var delivered bool
	var mu sync.Mutex
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		delivered = true
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer downstream.Close()
	b := service.NewStreamBuilder()
	require.NoError(t, b.SetYAML(fmt.Sprintf("input:\n  tyk_kafka:\n    seed_brokers: [%q]\n    topics: [%q]\n    consumer_group: negative-%d\n    tls:\n      enabled: true\n      root_cas_file: %q%s\noutput:\n  http_client:\n    url: %q\n    verb: POST\n", brokers[0], topic, time.Now().UnixNano(), caPath, client, downstream.URL)))
	s, err := b.Build()
	require.NoError(t, err)
	runCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(runCtx) }()
	select {
	case <-done:
	case <-runCtx.Done():
	}
	stopCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	_ = s.Stop(stopCtx)
	mu.Lock()
	defer mu.Unlock()
	require.False(t, delivered, "connector delivered despite rejected TLS credentials")
}

func generateKafkaTLSMaterial(t *testing.T) kafkaTLSMaterial {
	t.Helper()
	now := time.Now()
	serial := func() *big.Int {
		n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
		require.NoError(t, e)
		return n
	}
	key := func() *rsa.PrivateKey { k, e := rsa.GenerateKey(rand.Reader, 2048); require.NoError(t, e); return k }
	encodeKey := func(k *rsa.PrivateKey) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
	}
	caKey := key()
	caT := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Tyk Kafka Test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, e := x509.CreateCertificate(rand.Reader, caT, caT, &caKey.PublicKey, caKey)
	require.NoError(t, e)
	caCert, e := x509.ParseCertificate(caDER)
	require.NoError(t, e)
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	issue := func(cn string, server bool) (string, string) {
		k := key()
		tmpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: cn}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
		if server {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			tmpl.DNSNames = []string{"localhost"}
			tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		} else {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, e := x509.CreateCertificate(rand.Reader, tmpl, caCert, &k.PublicKey, caKey)
		require.NoError(t, e)
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), encodeKey(k)
	}
	serverCert, serverKey := issue("localhost", true)
	clientCert, clientKey := issue("tyk-client", false)
	rogueKey := key()
	rogue := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Rogue CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rogueDER, e := x509.CreateCertificate(rand.Reader, rogue, rogue, &rogueKey.PublicKey, rogueKey)
	require.NoError(t, e)
	return kafkaTLSMaterial{ca: caPEM, serverCert: serverCert, serverKey: serverKey, clientCert: clientCert, clientKey: clientKey, rogueCA: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rogueDER}))}
}

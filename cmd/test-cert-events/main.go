package main

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/internal/certcheck"
)

func main() {
	webhookURL := "https://webhook.site/34737299-0864-41f6-8c89-5752db8e24d0"

	fmt.Println("Testing upstream certificate webhook...")
	testUpstreamCertificate(webhookURL)

	time.Sleep(2 * time.Second)

	fmt.Println("Testing client certificate webhook...")
	testClientCertificate(webhookURL)
}

func testUpstreamCertificate(webhookURL string) {
	// Create certificate expiring in 20 days
	_, _, certPEM, _ := certs.GenCertificate(&x509.Certificate{
		Subject:  pkix.Name{CommonName: "upstream.test.com"},
		NotAfter: time.Now().Add(20 * 24 * time.Hour),
	}, false)

	// Parse certificate to get Leaf
	block, _ := pem.Decode(certPEM)
	parsedCert, _ := x509.ParseCertificate(block.Bytes)

	// Create event metadata with upstream type
	eventMeta := certcheck.EventCertificateExpiringSoonMeta{
		CertID:        "upstream-test-cert-id",
		CertName:      "upstream.test.com",
		ExpiresAt:     parsedCert.NotAfter,
		DaysRemaining: 20,
		CertRole:      "upstream",
		APIID:         "test-api-upstream",
	}
	eventMeta.Message = "Certificate upstream.test.com is expiring in 20 days"

	sendWebhook(webhookURL, "CertificateExpiringSoon", eventMeta)
}

func testClientCertificate(webhookURL string) {
	// Create certificate expiring in 15 days
	_, _, certPEM, _ := certs.GenCertificate(&x509.Certificate{
		Subject:  pkix.Name{CommonName: "client.test.com"},
		NotAfter: time.Now().Add(15 * 24 * time.Hour),
	}, false)

	// Parse certificate to get Leaf
	block, _ := pem.Decode(certPEM)
	parsedCert, _ := x509.ParseCertificate(block.Bytes)

	// Create event metadata with client type
	eventMeta := certcheck.EventCertificateExpiringSoonMeta{
		CertID:        "client-test-cert-id",
		CertName:      "client.test.com",
		ExpiresAt:     parsedCert.NotAfter,
		DaysRemaining: 15,
		CertRole:      "client",
		APIID:         "test-api-client",
	}
	eventMeta.Message = "Certificate client.test.com is expiring in 15 days"

	sendWebhook(webhookURL, "CertificateExpiringSoon", eventMeta)
}

func sendWebhook(webhookURL string, eventType string, meta interface{}) {
	payload := map[string]interface{}{
		"event":          eventType,
		"message":        meta.(certcheck.EventCertificateExpiringSoonMeta).Message,
		"cert_id":        meta.(certcheck.EventCertificateExpiringSoonMeta).CertID,
		"cert_name":      meta.(certcheck.EventCertificateExpiringSoonMeta).CertName,
		"expires_at":     meta.(certcheck.EventCertificateExpiringSoonMeta).ExpiresAt.Format(time.RFC3339),
		"days_remaining": meta.(certcheck.EventCertificateExpiringSoonMeta).DaysRemaining,
		"cert_role":      meta.(certcheck.EventCertificateExpiringSoonMeta).CertRole,
		"api_id":         meta.(certcheck.EventCertificateExpiringSoonMeta).APIID,
		"timestamp":      time.Now().Format(time.RFC3339),
	}

	jsonData, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Event-Type", eventType)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error sending webhook: %v\n", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("Webhook sent: %s - Status: %d\n", meta.(certcheck.EventCertificateExpiringSoonMeta).CertRole, resp.StatusCode)
}

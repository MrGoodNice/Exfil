package main

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// H4: the SNI of an opaque/pinning connection (handshake done, no HTTP request) must reach the
// failed-handshake event. It can only come from ca.GetCertificate -> flow.noteTLSHost, which needs
// hello.Context() to carry the flow. Because trackingTLSListener.Accept returns *trackingTLSConn
// (embedding *tls.Conn, not *tls.Conn itself), net/http's `c.rwc.(*tls.Conn)` assertion fails, so
// the server never calls HandshakeContext(connCtx); the handshake runs lazily with context.Background
// and the flow is lost. This test drives the REAL listener end-to-end and was RED before the fix.
func TestH4RealListenerCapturesSNIOnOpaqueHandshake(t *testing.T) {
	dir := t.TempDir()
	httpLogger, err := openEventLogger(filepath.Join(dir, "http.jsonl"))
	if err != nil {
		t.Fatalf("openEventLogger http: %v", err)
	}
	defer httpLogger.Close()
	networkLogger, err := openEventLogger(filepath.Join(dir, "network.jsonl"))
	if err != nil {
		t.Fatalf("openEventLogger network: %v", err)
	}
	defer networkLogger.Close()

	ca, err := newCertificateAuthority(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatalf("newCertificateAuthority: %v", err)
	}

	// Wire the TLS server exactly like run() does.
	base, err := newTrackingListener("127.0.0.1:0", networkLogger, httpLogger, nil, "run-1", "sample-1", true)
	if err != nil {
		t.Fatalf("newTrackingListener: %v", err)
	}
	tlsConfig := &tls.Config{GetCertificate: ca.GetCertificate, MinVersion: tls.VersionTLS12}
	tlsServer := &http.Server{
		Handler:           syntheticHandler(httpLogger, "run-1", "sample-1", true, nil),
		ReadHeaderTimeout: 5 * time.Second,
		ConnContext:       connContext,
		TLSConfig:         tlsConfig,
	}
	go func() { _ = tlsServer.Serve(&trackingTLSListener{trackingListener: base, config: tlsConfig}) }()
	defer tlsServer.Close()

	const sni = "pinned.example.test"
	conn, err := tls.Dial("tcp", base.Addr().String(), &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // client accepts our CA-signed leaf; models a client that then bails
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls.Dial (handshake) failed: %v", err)
	}
	// Opaque / pinning: handshake completed, send NO HTTP request, just close.
	_ = conn.Close()

	// Poll for the server to observe the close and log the failed-handshake event.
	var event map[string]any
	for i := 0; i < 150; i++ {
		events := readOpaqueEvents(filepath.Join(dir, "http.jsonl"))
		if len(events) > 0 {
			event = events[len(events)-1]
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if event == nil {
		t.Fatalf("no failed-handshake event was logged")
	}
	if event["opaque_reason"] != "failed-handshake" {
		t.Fatalf("expected opaque failed-handshake event, got: %#v", event)
	}
	if event["host"] != sni {
		t.Fatalf("H4 CONFIRMED: opaque host = %#v, want %q (SNI from handshake was dropped)", event["host"], sni)
	}
}

func readOpaqueEvents(path string) []map[string]any {
	raw, err := os.ReadFile(path)
	if err != nil || len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	var events []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var event map[string]any
		if json.Unmarshal([]byte(line), &event) == nil {
			events = append(events, event)
		}
	}
	return events
}

package main

import (
	crypto_rand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultListenAddr = ":80"
	defaultTLSAddr    = ":443"
	syntheticBody     = "exfil-analyzer synthetic response\n"
)

type httpEvent struct {
	Timestamp          string   `json:"ts"`
	RunID              string   `json:"run_id"`
	SampleID           string   `json:"sample_id"`
	FlowID             *string  `json:"flow_id"`
	Method             *string  `json:"method"`
	Host               string   `json:"host"`
	Path               *string  `json:"path"`
	TLS                bool     `json:"tls"`
	OpaqueReason       *string  `json:"opaque_reason"`
	CanaryMatch        []string `json:"canary_match"`
	RequestBodySHA256  *string  `json:"request_body_sha256"`
	ResponseBodySHA256 *string  `json:"response_body_sha256"`
	Upstream           bool     `json:"upstream"`
}

type eventLogger struct {
	mu   sync.Mutex
	file *os.File
	seq  uint64
}

type certificateAuthority struct {
	mu    sync.Mutex
	cert  *x509.Certificate
	key   *rsa.PrivateKey
	cache map[string]*tls.Certificate
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "http-listener: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	listenAddr := getenvDefault("EXFIL_HTTP_LISTEN", defaultListenAddr)
	logPath := getenvDefault("EXFIL_HTTP_LOG", "/logs/http.jsonl")
	logger, err := openEventLogger(logPath)
	if err != nil {
		return err
	}
	defer logger.Close()

	runID := getenvDefault("EXFIL_RUN_ID", "unknown-run")
	sampleID := getenvDefault("EXFIL_SAMPLE_ID", "unknown-sample")
	handler := syntheticHandler(logger, runID, sampleID, false)
	server := &http.Server{
		Addr:              listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if caCertPath := os.Getenv("EXFIL_TLS_CA_CERT"); caCertPath != "" {
		ca, err := newCertificateAuthority(caCertPath)
		if err != nil {
			return err
		}
		tlsServer := &http.Server{
			Addr:              getenvDefault("EXFIL_TLS_LISTEN", defaultTLSAddr),
			Handler:           syntheticHandler(logger, runID, sampleID, true),
			ReadHeaderTimeout: 5 * time.Second,
			TLSConfig: &tls.Config{
				// ref: go doc crypto/tls Config.GetCertificate on Go 1.26.
				GetCertificate: ca.GetCertificate,
				MinVersion:     tls.VersionTLS12,
			},
		}
		errCh := make(chan error, 2)
		go func() {
			errCh <- tlsServer.ListenAndServeTLS("", "")
		}()
		go func() {
			errCh <- server.ListenAndServe()
		}()
		return <-errCh
	}
	return server.ListenAndServe()
}

func getenvDefault(name, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}

func openEventLogger(path string) (*eventLogger, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &eventLogger{file: file}, nil
}

func (logger *eventLogger) Close() error {
	return logger.file.Close()
}

func syntheticHandler(logger *eventLogger, runID, sampleID string, tlsTerminated bool) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		// ref: /home/mrg/Desktop/exfil-step-a-refs/flare-fakenet-ng/fakenet/listeners/HTTPListener.py:63
		// Pattern: select a synthetic response from request host/path; F1.1 always uses the fallback synthetic body.
		body, _ := io.ReadAll(request.Body)
		flowID := logger.nextFlowID()
		method := request.Method
		path := request.URL.RequestURI()
		responseHash := sha256Hex([]byte(syntheticBody))
		event := httpEvent{
			Timestamp:          time.Now().UTC().Format(time.RFC3339Nano),
			RunID:              runID,
			SampleID:           sampleID,
			FlowID:             &flowID,
			Method:             &method,
			Host:               request.Host,
			Path:               &path,
			TLS:                tlsTerminated,
			OpaqueReason:       nil,
			CanaryMatch:        []string{},
			RequestBodySHA256:  bodyHash(body),
			ResponseBodySHA256: &responseHash,
			Upstream:           false,
		}
		if err := logger.write(event); err != nil {
			http.Error(writer, "honeynet log error", http.StatusInternalServerError)
			return
		}

		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.Header().Set("X-Exfil-Honeynet", "synthetic")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(syntheticBody))
	})
}

func (logger *eventLogger) nextFlowID() string {
	next := atomic.AddUint64(&logger.seq, 1)
	return fmt.Sprintf("honeynet-http-%d-%d", time.Now().UnixNano(), next)
}

func (logger *eventLogger) write(event httpEvent) error {
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	logger.mu.Lock()
	defer logger.mu.Unlock()
	if _, err := logger.file.Write(append(encoded, '\n')); err != nil {
		return err
	}
	return logger.file.Sync()
}

func bodyHash(body []byte) *string {
	if len(body) == 0 {
		return nil
	}
	hash := sha256Hex(body)
	return &hash
}

func sha256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func newCertificateAuthority(certPath string) (*certificateAuthority, error) {
	// ref: /home/mrg/Desktop/exfil-step-a-refs/mitmproxy/mitmproxy/certs.py:232
	// Pattern: create one per-run CA and use it to mint per-SNI leaf certificates.
	key, err := rsa.GenerateKey(crypto_rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Exfil Analyzer Honeynet CA", Organization: []string{"Exfil Analyzer"}},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(crypto_rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if certPEM == nil {
		return nil, fmt.Errorf("failed to PEM encode CA certificate")
	}
	if dir := filepath.Dir(certPath); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, err
	}
	return &certificateAuthority{cert: cert, key: key, cache: map[string]*tls.Certificate{}}, nil
}

func (ca *certificateAuthority) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// ref: go doc crypto/tls Config.GetCertificate on Go 1.26.
	serverName := normalizeServerName(hello.ServerName)
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if cert, ok := ca.cache[serverName]; ok {
		return cert, nil
	}
	cert, err := ca.mintLeaf(serverName)
	if err != nil {
		return nil, err
	}
	ca.cache[serverName] = cert
	return cert, nil
}

func (ca *certificateAuthority) mintLeaf(serverName string) (*tls.Certificate, error) {
	// ref: /home/mrg/Desktop/exfil-step-a-refs/mitmproxy/mitmproxy/certs.py:314
	leafKey, err := rsa.GenerateKey(crypto_rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonNameFor(serverName), Organization: []string{"Exfil Analyzer"}},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(6 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(serverName); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{serverName}
	}
	der, err := x509.CreateCertificate(crypto_rand.Reader, template, ca.cert, &leafKey.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, ca.cert.Raw},
		PrivateKey:  leafKey,
		Leaf:        leaf,
	}, nil
}

func normalizeServerName(serverName string) string {
	serverName = strings.TrimSpace(strings.TrimSuffix(serverName, "."))
	if serverName == "" {
		return "exfil-analyzer.invalid"
	}
	return strings.ToLower(serverName)
}

func commonNameFor(serverName string) string {
	if len(serverName) < 64 {
		return serverName
	}
	return ""
}

func randomSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return crypto_rand.Int(crypto_rand.Reader, limit)
}

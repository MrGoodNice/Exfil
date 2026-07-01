package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultListenAddr = ":80"
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

	handler := syntheticHandler(logger, getenvDefault("EXFIL_RUN_ID", "unknown-run"), getenvDefault("EXFIL_SAMPLE_ID", "unknown-sample"))
	server := &http.Server{
		Addr:              listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
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

func syntheticHandler(logger *eventLogger, runID, sampleID string) http.Handler {
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
			TLS:                false,
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

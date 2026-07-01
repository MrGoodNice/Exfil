package main

import (
	"context"
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
	"strconv"
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

type networkEvent struct {
	Timestamp   string  `json:"ts"`
	RunID       string  `json:"run_id"`
	SampleID    string  `json:"sample_id"`
	Source      string  `json:"source"`
	FlowID      *string `json:"flow_id"`
	PID         *int    `json:"pid"`
	SrcIP       *string `json:"src_ip"`
	SrcPort     *int    `json:"src_port"`
	DstIP       string  `json:"dst_ip"`
	DstPort     int     `json:"dst_port"`
	Proto       string  `json:"proto"`
	Retval      *int    `json:"retval"`
	ContainerID *string `json:"container_id"`
	CgroupID    *string `json:"cgroup_id"`
}

type eventLogger struct {
	mu   sync.Mutex
	file *os.File
	seq  uint64
}

type flowContextKey struct{}

type connectionFlow struct {
	id           string
	tls          bool
	requestSeen  atomic.Bool
	opaqueLogged atomic.Bool
	hostMu       sync.Mutex
	host         string
}

type trackingListener struct {
	net.Listener
	networkLogger *eventLogger
	httpLogger    *eventLogger
	matcher       *canaryMatcher
	runID         string
	sampleID      string
	tls           bool
}

type trackingTLSListener struct {
	*trackingListener
	config *tls.Config
}

type trackingConn struct {
	net.Conn
	flow               *connectionFlow
	httpLogger         *eventLogger
	matcher            *canaryMatcher
	runID              string
	sampleID           string
	logFailedHandshake bool
}

type trackingTLSConn struct {
	*tls.Conn
	flow *connectionFlow
}

type canaryCatalog struct {
	Secrets []canarySecret `json:"secrets"`
}

type canarySecret struct {
	SecretID   string `json:"secret_id"`
	MatchToken string `json:"match_token"`
}

type canaryMatcher struct {
	secrets []canarySecret
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
	httpLogPath := getenvDefault("EXFIL_HTTP_LOG", "/logs/http.jsonl")
	httpLogger, err := openEventLogger(httpLogPath)
	if err != nil {
		return err
	}
	defer httpLogger.Close()
	networkLogPath := getenvDefault("EXFIL_NETWORK_LOG", "/logs/network.jsonl")
	networkLogger, err := openEventLogger(networkLogPath)
	if err != nil {
		return err
	}
	defer networkLogger.Close()

	runID := getenvDefault("EXFIL_RUN_ID", "unknown-run")
	sampleID := getenvDefault("EXFIL_SAMPLE_ID", "unknown-sample")
	matcher, err := loadCanaryMatcher(os.Getenv("EXFIL_CANARY_CATALOG"))
	if err != nil {
		return err
	}
	handler := syntheticHandler(httpLogger, runID, sampleID, false, matcher)
	listener, err := newTrackingListener(listenAddr, networkLogger, httpLogger, matcher, runID, sampleID, false)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		// ref: go doc net/http Server.ConnContext on Go 1.26.
		ConnContext: connContext,
	}
	if caCertPath := os.Getenv("EXFIL_TLS_CA_CERT"); caCertPath != "" {
		ca, err := newCertificateAuthority(caCertPath)
		if err != nil {
			return err
		}
		tlsAddr := getenvDefault("EXFIL_TLS_LISTEN", defaultTLSAddr)
		tlsListener, err := newTrackingListener(tlsAddr, networkLogger, httpLogger, matcher, runID, sampleID, true)
		if err != nil {
			return err
		}
		tlsConfig := &tls.Config{
			// ref: go doc crypto/tls Config.GetCertificate on Go 1.26.
			GetCertificate: ca.GetCertificate,
			MinVersion:     tls.VersionTLS12,
		}
		tlsServer := &http.Server{
			Addr:              tlsAddr,
			Handler:           syntheticHandler(httpLogger, runID, sampleID, true, matcher),
			ReadHeaderTimeout: 5 * time.Second,
			// ref: go doc net/http Server.ConnContext on Go 1.26.
			ConnContext: connContext,
			TLSConfig:   tlsConfig,
		}
		errCh := make(chan error, 2)
		go func() {
			// ref: go doc net/http Server.Serve and go doc crypto/tls Server on Go 1.26.
			errCh <- tlsServer.Serve(&trackingTLSListener{trackingListener: tlsListener, config: tlsConfig})
		}()
		go func() {
			// ref: go doc net/http Server.Serve on Go 1.26.
			errCh <- server.Serve(listener)
		}()
		return <-errCh
	}
	// ref: go doc net/http Server.Serve on Go 1.26.
	return server.Serve(listener)
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

func syntheticHandler(logger *eventLogger, runID, sampleID string, tlsTerminated bool, matcher *canaryMatcher) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		// ref: /home/mrg/Desktop/exfil-step-a-refs/flare-fakenet-ng/fakenet/listeners/HTTPListener.py:63
		// Pattern: select a synthetic response from request host/path; F1.1 always uses the fallback synthetic body.
		flowID := logger.nextFlowID()
		if flow := flowFromContext(request.Context()); flow != nil {
			flow.markRequestSeen()
			flow.noteTLSHost(request.Host)
			flowID = flow.id
		}
		body, _ := io.ReadAll(request.Body)
		method := request.Method
		path := request.URL.RequestURI()
		canaryMatches := matcher.match(request.Host, request.Header, path, body)
		loggedHost := matcher.redact(request.Host)
		loggedPath := matcher.redact(path)
		responseHash := sha256Hex([]byte(syntheticBody))
		event := httpEvent{
			Timestamp:          time.Now().UTC().Format(time.RFC3339Nano),
			RunID:              runID,
			SampleID:           sampleID,
			FlowID:             &flowID,
			Method:             &method,
			Host:               loggedHost,
			Path:               &loggedPath,
			TLS:                tlsTerminated,
			OpaqueReason:       nil,
			CanaryMatch:        canaryMatches,
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
	return fmt.Sprintf("honeynet-flow-%d-%d", time.Now().UnixNano(), next)
}

func (logger *eventLogger) write(event any) error {
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

func loadCanaryMatcher(path string) (*canaryMatcher, error) {
	if path == "" {
		return nil, nil
	}
	// ref: go doc os.ReadFile on Go 1.26.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read canary catalog: %w", err)
	}
	var catalog canaryCatalog
	// ref: go doc encoding/json.Unmarshal on Go 1.26.
	if err := json.Unmarshal(raw, &catalog); err != nil {
		return nil, fmt.Errorf("parse canary catalog: %w", err)
	}
	secrets := make([]canarySecret, 0, len(catalog.Secrets))
	for _, secret := range catalog.Secrets {
		if secret.SecretID == "" || secret.MatchToken == "" {
			continue
		}
		secrets = append(secrets, secret)
	}
	return &canaryMatcher{secrets: secrets}, nil
}

func (matcher *canaryMatcher) match(host string, headers http.Header, requestURI string, body []byte) []string {
	if matcher == nil || len(matcher.secrets) == 0 {
		return []string{}
	}
	candidates := []string{host, requestURI, string(body)}
	// ref: go doc net/http Request.Header on Go 1.26.
	for _, values := range headers {
		candidates = append(candidates, values...)
	}
	matches := make([]string, 0, len(matcher.secrets))
	seen := make(map[string]bool, len(matcher.secrets))
	for _, secret := range matcher.secrets {
		if seen[secret.SecretID] {
			continue
		}
		for _, candidate := range candidates {
			// ref: go doc strings.Contains on Go 1.26.
			if strings.Contains(candidate, secret.MatchToken) {
				matches = append(matches, secret.SecretID)
				seen[secret.SecretID] = true
				break
			}
		}
	}
	return matches
}

func (matcher *canaryMatcher) redact(value string) string {
	if matcher == nil || value == "" {
		return value
	}
	redacted := value
	for _, secret := range matcher.secrets {
		if secret.SecretID == "" || secret.MatchToken == "" {
			continue
		}
		// ref: go doc strings.ReplaceAll on Go 1.26.
		redacted = strings.ReplaceAll(redacted, secret.MatchToken, "[canary:"+secret.SecretID+"]")
	}
	return redacted
}

func newConnectionFlow(id string, tlsTerminated bool) *connectionFlow {
	return &connectionFlow{id: id, tls: tlsTerminated}
}

func newTrackingListener(addr string, networkLogger, httpLogger *eventLogger, matcher *canaryMatcher, runID, sampleID string, tlsTerminated bool) (*trackingListener, error) {
	// ref: go doc net.Listen on Go 1.26.
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &trackingListener{
		Listener:      listener,
		networkLogger: networkLogger,
		httpLogger:    httpLogger,
		matcher:       matcher,
		runID:         runID,
		sampleID:      sampleID,
		tls:           tlsTerminated,
	}, nil
}

func (listener *trackingListener) Accept() (net.Conn, error) {
	conn, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}
	flow := newConnectionFlow(listener.networkLogger.nextFlowID(), listener.tls)
	if err := logNetworkEvent(listener.networkLogger, listener.runID, listener.sampleID, flow, conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &trackingConn{
		Conn:               conn,
		flow:               flow,
		httpLogger:         listener.httpLogger,
		matcher:            listener.matcher,
		runID:              listener.runID,
		sampleID:           listener.sampleID,
		logFailedHandshake: listener.tls,
	}, nil
}

func (listener *trackingTLSListener) Accept() (net.Conn, error) {
	conn, err := listener.trackingListener.Accept()
	if err != nil {
		return nil, err
	}
	tracked, ok := conn.(*trackingConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("tracking TLS listener accepted unexpected connection type %T", conn)
	}
	// ref: go doc crypto/tls Server on Go 1.26.
	return &trackingTLSConn{Conn: tls.Server(tracked, listener.config), flow: tracked.flow}, nil
}

func (conn *trackingConn) Close() error {
	err := conn.Conn.Close()
	if conn.logFailedHandshake {
		if logErr := logFailedTLSHandshake(conn.httpLogger, conn.runID, conn.sampleID, conn.flow, conn.matcher); err == nil {
			err = logErr
		}
	}
	return err
}

func connContext(ctx context.Context, conn net.Conn) context.Context {
	if tracked, ok := conn.(*trackingConn); ok {
		// ref: go doc context.WithValue on Go 1.26.
		return context.WithValue(ctx, flowContextKey{}, tracked.flow)
	}
	if tracked, ok := conn.(*trackingTLSConn); ok {
		// ref: go doc context.WithValue on Go 1.26.
		return context.WithValue(ctx, flowContextKey{}, tracked.flow)
	}
	return ctx
}

func flowFromContext(ctx context.Context) *connectionFlow {
	if ctx == nil {
		return nil
	}
	flow, _ := ctx.Value(flowContextKey{}).(*connectionFlow)
	return flow
}

func logNetworkEvent(logger *eventLogger, runID, sampleID string, flow *connectionFlow, conn net.Conn) error {
	// ref: go doc net Conn.RemoteAddr and go doc net Conn.LocalAddr on Go 1.26.
	srcIP, srcPort := endpointFromAddr(conn.RemoteAddr())
	dstIP, dstPort := endpointFromAddr(conn.LocalAddr())
	event := networkEvent{
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
		RunID:       runID,
		SampleID:    sampleID,
		Source:      "honeynet",
		FlowID:      &flow.id,
		PID:         nil,
		SrcIP:       stringPtr(srcIP),
		SrcPort:     intPtr(srcPort),
		DstIP:       dstIP,
		DstPort:     dstPort,
		Proto:       "tcp",
		Retval:      nil,
		ContainerID: nil,
		CgroupID:    nil,
	}
	return logger.write(event)
}

func logFailedTLSHandshake(logger *eventLogger, runID, sampleID string, flow *connectionFlow, matcher *canaryMatcher) error {
	if !flow.tls || flow.requestSeen.Load() || !flow.opaqueLogged.CompareAndSwap(false, true) {
		return nil
	}
	opaqueReason := "failed-handshake"
	event := httpEvent{
		Timestamp:          time.Now().UTC().Format(time.RFC3339Nano),
		RunID:              runID,
		SampleID:           sampleID,
		FlowID:             &flow.id,
		Method:             nil,
		Host:               matcher.redact(flow.hostOr("unknown")),
		Path:               nil,
		TLS:                true,
		OpaqueReason:       &opaqueReason,
		CanaryMatch:        []string{},
		RequestBodySHA256:  nil,
		ResponseBodySHA256: nil,
		Upstream:           false,
	}
	return logger.write(event)
}

func (flow *connectionFlow) markRequestSeen() {
	flow.requestSeen.Store(true)
}

func (flow *connectionFlow) noteTLSHost(host string) {
	host = normalizeServerName(stripOptionalPort(host))
	if host == "" || host == "exfil-analyzer.invalid" {
		return
	}
	flow.hostMu.Lock()
	defer flow.hostMu.Unlock()
	if flow.host == "" {
		flow.host = host
	}
}

func (flow *connectionFlow) hostOr(fallback string) string {
	flow.hostMu.Lock()
	defer flow.hostMu.Unlock()
	if flow.host != "" {
		return flow.host
	}
	return fallback
}

func endpointFromAddr(addr net.Addr) (string, int) {
	if addr == nil {
		return "unknown", 0
	}
	host, portText, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String(), 0
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return host, 0
	}
	return host, port
}

func stringPtr(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func intPtr(value int) *int {
	return &value
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
	if flow := flowFromContext(hello.Context()); flow != nil {
		// ref: go doc crypto/tls ClientHelloInfo.Context on Go 1.26.
		flow.noteTLSHost(serverName)
	}
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

func stripOptionalPort(host string) string {
	host = strings.TrimSpace(host)
	if splitHost, _, err := net.SplitHostPort(host); err == nil {
		return splitHost
	}
	return strings.TrimSuffix(host, ".")
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

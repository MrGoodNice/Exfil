package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSyntheticHandlerLogsGetAndPost(t *testing.T) {
	dir := t.TempDir()
	logger, err := openEventLogger(filepath.Join(dir, "http.jsonl"))
	if err != nil {
		t.Fatalf("openEventLogger failed: %v", err)
	}
	defer logger.Close()

	handler := syntheticHandler(logger, "run-1", "sample-1", false, nil)
	getReq := httptest.NewRequest(http.MethodGet, "http://example.test/download?x=1", nil)
	getReq.Host = "example.test"
	getResp := httptest.NewRecorder()
	handler.ServeHTTP(getResp, getReq)
	if getResp.Code != http.StatusOK {
		t.Fatalf("GET code = %d", getResp.Code)
	}
	if !strings.Contains(getResp.Body.String(), syntheticBody) {
		t.Fatalf("GET body = %q", getResp.Body.String())
	}

	postReq := httptest.NewRequest(http.MethodPost, "http://example.test/submit", strings.NewReader("payload=f1-1"))
	postReq.Host = "example.test"
	postResp := httptest.NewRecorder()
	handler.ServeHTTP(postResp, postReq)
	if postResp.Code != http.StatusOK {
		t.Fatalf("POST code = %d", postResp.Code)
	}

	events := readEvents(t, filepath.Join(dir, "http.jsonl"))
	if len(events) != 2 {
		t.Fatalf("event count = %d: %#v", len(events), events)
	}
	requireEvent(t, events[0], "GET", "/download?x=1", false, false)
	requireEvent(t, events[1], "POST", "/submit", true, false)
}

func TestSyntheticHandlerLogsTLSFlag(t *testing.T) {
	dir := t.TempDir()
	logger, err := openEventLogger(filepath.Join(dir, "http.jsonl"))
	if err != nil {
		t.Fatalf("openEventLogger failed: %v", err)
	}
	defer logger.Close()

	handler := syntheticHandler(logger, "run-1", "sample-1", true, nil)
	request := httptest.NewRequest(http.MethodPost, "https://example.test/submit", strings.NewReader("payload=f1-2a"))
	request.Host = "example.test"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("TLS POST code = %d", response.Code)
	}

	events := readEvents(t, filepath.Join(dir, "http.jsonl"))
	if len(events) != 1 {
		t.Fatalf("event count = %d: %#v", len(events), events)
	}
	requireEvent(t, events[0], "POST", "/submit", true, true)
}

func TestCertificateAuthorityMintsLeafWithoutWritingPrivateKey(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	ca, err := newCertificateAuthority(caPath)
	if err != nil {
		t.Fatalf("newCertificateAuthority failed: %v", err)
	}
	raw, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if !strings.Contains(string(raw), "BEGIN CERTIFICATE") {
		t.Fatalf("CA cert PEM missing certificate block: %q", raw)
	}
	if strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatalf("CA private key leaked into CA cert PEM")
	}

	leaf, err := ca.GetCertificate(&tls.ClientHelloInfo{ServerName: "Example.Test"})
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if leaf.Leaf == nil {
		t.Fatalf("leaf certificate was not parsed")
	}
	if err := leaf.Leaf.VerifyHostname("example.test"); err != nil {
		t.Fatalf("VerifyHostname failed: %v", err)
	}
	if err := leaf.Leaf.CheckSignatureFrom(ca.cert); err != nil {
		t.Fatalf("leaf not signed by CA: %v", err)
	}
}

func TestConnectionFlowJoinsNetworkAndHTTPEvents(t *testing.T) {
	dir := t.TempDir()
	httpLogger, err := openEventLogger(filepath.Join(dir, "http.jsonl"))
	if err != nil {
		t.Fatalf("openEventLogger http failed: %v", err)
	}
	defer httpLogger.Close()
	networkLogger, err := openEventLogger(filepath.Join(dir, "network.jsonl"))
	if err != nil {
		t.Fatalf("openEventLogger network failed: %v", err)
	}
	defer networkLogger.Close()

	flow := newConnectionFlow("flow-unit-1", false)
	conn := fakeConn{
		remote: fakeAddr("172.18.0.44:43123"),
		local:  fakeAddr("172.18.0.2:80"),
	}
	if err := logNetworkEvent(networkLogger, "run-1", "sample-1", flow, conn); err != nil {
		t.Fatalf("logNetworkEvent failed: %v", err)
	}

	handler := syntheticHandler(httpLogger, "run-1", "sample-1", false, nil)
	request := httptest.NewRequest(http.MethodGet, "http://example.test/one", nil)
	request.Host = "example.test"
	request = request.WithContext(context.WithValue(request.Context(), flowContextKey{}, flow))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET code = %d", response.Code)
	}

	networkEvents := readEvents(t, filepath.Join(dir, "network.jsonl"))
	httpEvents := readEvents(t, filepath.Join(dir, "http.jsonl"))
	if len(networkEvents) != 1 || len(httpEvents) != 1 {
		t.Fatalf("event counts: network=%#v http=%#v", networkEvents, httpEvents)
	}
	if networkEvents[0]["flow_id"] != httpEvents[0]["flow_id"] {
		t.Fatalf("flow_id mismatch: network=%#v http=%#v", networkEvents[0], httpEvents[0])
	}
	requireNetworkEvent(t, networkEvents[0], "flow-unit-1", "172.18.0.44", 43123, "172.18.0.2", 80)
}

func TestFailedTLSHandshakeLogsOpaqueHTTPEventWithConnectionFlow(t *testing.T) {
	dir := t.TempDir()
	httpLogger, err := openEventLogger(filepath.Join(dir, "http.jsonl"))
	if err != nil {
		t.Fatalf("openEventLogger http failed: %v", err)
	}
	defer httpLogger.Close()
	networkLogger, err := openEventLogger(filepath.Join(dir, "network.jsonl"))
	if err != nil {
		t.Fatalf("openEventLogger network failed: %v", err)
	}
	defer networkLogger.Close()

	flow := newConnectionFlow("flow-opaque-1", true)
	flow.noteTLSHost("Opaque.Example.Test")
	conn := fakeConn{
		remote: fakeAddr("172.18.0.55:45234"),
		local:  fakeAddr("172.18.0.2:443"),
	}
	if err := logNetworkEvent(networkLogger, "run-1", "sample-1", flow, conn); err != nil {
		t.Fatalf("logNetworkEvent failed: %v", err)
	}
	if err := logFailedTLSHandshake(httpLogger, "run-1", "sample-1", flow, nil); err != nil {
		t.Fatalf("logFailedTLSHandshake failed: %v", err)
	}

	networkEvents := readEvents(t, filepath.Join(dir, "network.jsonl"))
	httpEvents := readEvents(t, filepath.Join(dir, "http.jsonl"))
	if len(networkEvents) != 1 || len(httpEvents) != 1 {
		t.Fatalf("event counts: network=%#v http=%#v", networkEvents, httpEvents)
	}
	if networkEvents[0]["flow_id"] != httpEvents[0]["flow_id"] {
		t.Fatalf("flow_id mismatch: network=%#v http=%#v", networkEvents[0], httpEvents[0])
	}
	if httpEvents[0]["tls"] != true || httpEvents[0]["opaque_reason"] != "failed-handshake" {
		t.Fatalf("bad opaque TLS event: %#v", httpEvents[0])
	}
	if httpEvents[0]["method"] != nil || httpEvents[0]["path"] != nil {
		t.Fatalf("failed-handshake request fields must be null: %#v", httpEvents[0])
	}
	if httpEvents[0]["host"] != "opaque.example.test" {
		t.Fatalf("failed-handshake host = %#v", httpEvents[0]["host"])
	}
	requireNetworkEvent(t, networkEvents[0], "flow-opaque-1", "172.18.0.55", 45234, "172.18.0.2", 443)
}

func TestFailedTLSHandshakeRedactsCanarySNIWithoutMatching(t *testing.T) {
	dir := t.TempDir()
	httpLogger, err := openEventLogger(filepath.Join(dir, "http.jsonl"))
	if err != nil {
		t.Fatalf("openEventLogger http failed: %v", err)
	}
	defer httpLogger.Close()

	const token = "host-opaque-token"
	const secretID = "canary_rsa-opaque"
	matcher := &canaryMatcher{secrets: []canarySecret{{SecretID: secretID, MatchToken: token}}}
	flow := newConnectionFlow("flow-opaque-host", true)
	flow.noteTLSHost(token + ".opaque.example.test")
	if err := logFailedTLSHandshake(httpLogger, "run-1", "sample-1", flow, matcher); err != nil {
		t.Fatalf("logFailedTLSHandshake failed: %v", err)
	}

	rawLog, err := os.ReadFile(filepath.Join(dir, "http.jsonl"))
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if strings.Contains(string(rawLog), token) {
		t.Fatalf("opaque event leaked raw SNI token: %q", rawLog)
	}
	events := readEvents(t, filepath.Join(dir, "http.jsonl"))
	if events[0]["host"] != "[canary:"+secretID+"].opaque.example.test" {
		t.Fatalf("opaque host = %#v", events[0]["host"])
	}
	if matches, ok := events[0]["canary_match"].([]any); !ok || len(matches) != 0 {
		t.Fatalf("opaque canary_match must stay empty: %#v", events[0]["canary_match"])
	}
}

func TestCanaryMatcherFindsBodyHeaderAndQueryWithoutLeakingToken(t *testing.T) {
	dir := t.TempDir()
	catalogPath := filepath.Join(dir, "canary.json")
	const token = "body-header-query-token"
	const secretID = "canary_rsa-bodyhead"
	if err := os.WriteFile(catalogPath, []byte(`{
  "run_id": "run-1",
  "generated_at": "2026-07-01T00:00:00Z",
  "secrets": [
    {"secret_id": "`+secretID+`", "type": "canary_rsa", "path": "/canary/canary_rsa", "match_token": "`+token+`"}
  ]
}`), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	matcher, err := loadCanaryMatcher(catalogPath)
	if err != nil {
		t.Fatalf("loadCanaryMatcher failed: %v", err)
	}

	logger, err := openEventLogger(filepath.Join(dir, "http.jsonl"))
	if err != nil {
		t.Fatalf("openEventLogger failed: %v", err)
	}
	defer logger.Close()

	handler := syntheticHandler(logger, "run-1", "sample-1", false, matcher)
	request := httptest.NewRequest(http.MethodPost, "http://example.test/submit?token="+token, strings.NewReader("body="+token))
	request.Host = "example.test"
	request.Header.Set("X-Canary", token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("POST code = %d", response.Code)
	}
	if strings.Contains(response.Body.String(), token) {
		t.Fatalf("synthetic response leaked raw token")
	}

	rawLog, err := os.ReadFile(filepath.Join(dir, "http.jsonl"))
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if strings.Contains(string(rawLog), token) {
		t.Fatalf("http event leaked raw token: %q", rawLog)
	}
	events := readEvents(t, filepath.Join(dir, "http.jsonl"))
	matches := events[0]["canary_match"].([]any)
	if len(matches) != 1 || matches[0] != secretID {
		t.Fatalf("canary_match = %#v", matches)
	}
}

func TestCanaryMatcherFindsAndRedactsHost(t *testing.T) {
	dir := t.TempDir()
	logger, err := openEventLogger(filepath.Join(dir, "http.jsonl"))
	if err != nil {
		t.Fatalf("openEventLogger failed: %v", err)
	}
	defer logger.Close()

	const token = "host-subdomain-token"
	const secretID = "canary_rsa-host"
	matcher := &canaryMatcher{secrets: []canarySecret{{SecretID: secretID, MatchToken: token}}}
	handler := syntheticHandler(logger, "run-1", "sample-1", true, matcher)
	request := httptest.NewRequest(http.MethodGet, "https://"+token+".example.test/download", nil)
	request.Host = token + ".example.test"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET code = %d", response.Code)
	}

	rawLog, err := os.ReadFile(filepath.Join(dir, "http.jsonl"))
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if strings.Contains(string(rawLog), token) {
		t.Fatalf("http event leaked raw host token: %q", rawLog)
	}
	events := readEvents(t, filepath.Join(dir, "http.jsonl"))
	if events[0]["host"] != "[canary:"+secretID+"].example.test" {
		t.Fatalf("host = %#v", events[0]["host"])
	}
	matches := events[0]["canary_match"].([]any)
	if len(matches) != 1 || matches[0] != secretID {
		t.Fatalf("canary_match = %#v", matches)
	}
}

func TestCanaryMatcherDedupsAndKeepsCatalogOrder(t *testing.T) {
	matcher := &canaryMatcher{secrets: []canarySecret{
		{SecretID: "first", MatchToken: "first-token"},
		{SecretID: "second", MatchToken: "second-token"},
	}}
	matches := matcher.match("clean.example.test", http.Header{"X-Test": []string{"second-token first-token"}}, "/path?x=first-token", []byte("second-token"))
	want := []string{"first", "second"}
	if strings.Join(matches, ",") != strings.Join(want, ",") {
		t.Fatalf("matches = %#v, want %#v", matches, want)
	}
}

func TestCanaryMatcherNoTokenMatchesEmpty(t *testing.T) {
	matcher := &canaryMatcher{secrets: []canarySecret{{SecretID: "first", MatchToken: "first-token"}}}
	matches := matcher.match("clean.example.test", http.Header{"X-Test": []string{"clean"}}, "/clean", []byte("clean"))
	if len(matches) != 0 {
		t.Fatalf("matches = %#v", matches)
	}
}

func TestScanRequestBodyStreamsHashAndMatchesTokenAcrossChunks(t *testing.T) {
	const token = "streaming-canary-token"
	const secretID = "canary_rsa-stream"
	prefixSize := int64(requestBodyChunkSize*3 + 17)
	suffixSize := int64(requestBodyChunkSize*2 + 5)
	matcher := &canaryMatcher{secrets: []canarySecret{{SecretID: secretID, MatchToken: token}}}
	body := io.MultiReader(
		&fixedByteReader{remaining: prefixSize, value: 'A'},
		strings.NewReader(token[:8]),
		strings.NewReader(token[8:]),
		&fixedByteReader{remaining: suffixSize, value: 'B'},
	)

	bodyHash, bodyMatches, err := scanRequestBody(body, matcher)
	if err != nil {
		t.Fatalf("scanRequestBody failed: %v", err)
	}
	if bodyHash == nil {
		t.Fatalf("body hash is nil")
	}
	if *bodyHash != expectedStreamHash(prefixSize, 'A', token, suffixSize, 'B') {
		t.Fatalf("request_body_sha256 = %s", *bodyHash)
	}
	matches := matcher.matchesFromSet(bodyMatches)
	if len(matches) != 1 || matches[0] != secretID {
		t.Fatalf("body matches = %#v", matches)
	}
}

func readEvents(t *testing.T, path string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	events := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("json decode failed: %v", err)
		}
		events = append(events, event)
	}
	return events
}

func requireNetworkEvent(t *testing.T, event map[string]any, flowID, srcIP string, srcPort float64, dstIP string, dstPort float64) {
	t.Helper()
	if event["run_id"] != "run-1" || event["sample_id"] != "sample-1" {
		t.Fatalf("bad network identity: %#v", event)
	}
	if event["source"] != "honeynet" || event["proto"] != "tcp" {
		t.Fatalf("bad network source/proto: %#v", event)
	}
	if event["flow_id"] != flowID {
		t.Fatalf("flow_id = %#v", event["flow_id"])
	}
	if event["pid"] != nil || event["retval"] != nil || event["container_id"] != nil || event["cgroup_id"] != nil {
		t.Fatalf("metadata must be null until aya: %#v", event)
	}
	if event["src_ip"] != srcIP || event["src_port"] != srcPort || event["dst_ip"] != dstIP || event["dst_port"] != dstPort {
		t.Fatalf("bad network endpoints: %#v", event)
	}
}

func requireEvent(t *testing.T, event map[string]any, method, path string, wantBodyHash bool, wantTLS bool) {
	t.Helper()
	if event["run_id"] != "run-1" || event["sample_id"] != "sample-1" {
		t.Fatalf("bad identity: %#v", event)
	}
	if event["method"] != method || event["host"] != "example.test" || event["path"] != path {
		t.Fatalf("bad request fields: %#v", event)
	}
	if event["tls"] != wantTLS || event["upstream"] != false || event["opaque_reason"] != nil {
		t.Fatalf("bad honeynet flags: %#v", event)
	}
	if matches, ok := event["canary_match"].([]any); !ok || len(matches) != 0 {
		t.Fatalf("canary_match = %#v", event["canary_match"])
	}
	if flowID, ok := event["flow_id"].(string); !ok || flowID == "" {
		t.Fatalf("flow_id = %#v", event["flow_id"])
	}
	if responseHash, ok := event["response_body_sha256"].(string); !ok || len(responseHash) != 64 {
		t.Fatalf("response_body_sha256 = %#v", event["response_body_sha256"])
	}
	requestHash, _ := event["request_body_sha256"].(string)
	if wantBodyHash && len(requestHash) != 64 {
		t.Fatalf("request_body_sha256 = %#v", event["request_body_sha256"])
	}
	if !wantBodyHash && event["request_body_sha256"] != nil {
		t.Fatalf("GET request_body_sha256 must be null: %#v", event["request_body_sha256"])
	}
}

type fakeAddr string

func (addr fakeAddr) Network() string { return "tcp" }
func (addr fakeAddr) String() string  { return string(addr) }

type fakeConn struct {
	net.Conn
	remote net.Addr
	local  net.Addr
}

func (conn fakeConn) RemoteAddr() net.Addr { return conn.remote }
func (conn fakeConn) LocalAddr() net.Addr  { return conn.local }

type fixedByteReader struct {
	remaining int64
	value     byte
}

func (reader *fixedByteReader) Read(buffer []byte) (int, error) {
	if reader.remaining == 0 {
		return 0, io.EOF
	}
	if int64(len(buffer)) > reader.remaining {
		buffer = buffer[:reader.remaining]
	}
	for index := range buffer {
		buffer[index] = reader.value
	}
	reader.remaining -= int64(len(buffer))
	return len(buffer), nil
}

func expectedStreamHash(prefixSize int64, prefix byte, token string, suffixSize int64, suffix byte) string {
	hasher := sha256.New()
	_, _ = io.Copy(hasher, &fixedByteReader{remaining: prefixSize, value: prefix})
	_, _ = hasher.Write([]byte(token))
	_, _ = io.Copy(hasher, &fixedByteReader{remaining: suffixSize, value: suffix})
	return hex.EncodeToString(hasher.Sum(nil))
}

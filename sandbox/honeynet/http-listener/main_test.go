package main

import (
	"encoding/json"
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

	handler := syntheticHandler(logger, "run-1", "sample-1")
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
	requireEvent(t, events[0], "GET", "/download?x=1", false)
	requireEvent(t, events[1], "POST", "/submit", true)
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

func requireEvent(t *testing.T, event map[string]any, method, path string, wantBodyHash bool) {
	t.Helper()
	if event["run_id"] != "run-1" || event["sample_id"] != "sample-1" {
		t.Fatalf("bad identity: %#v", event)
	}
	if event["method"] != method || event["host"] != "example.test" || event["path"] != path {
		t.Fatalf("bad request fields: %#v", event)
	}
	if event["tls"] != false || event["upstream"] != false || event["opaque_reason"] != nil {
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

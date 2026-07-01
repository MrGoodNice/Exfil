package main

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestParseQuestionAndBuildAResponse(t *testing.T) {
	query := dnsQuery(t, 0x1234, "f1-0.example.test", 1)
	question, err := parseQuestion(query)
	if err != nil {
		t.Fatalf("parseQuestion failed: %v", err)
	}
	if question.name != "f1-0.example.test" {
		t.Fatalf("query name = %q", question.name)
	}
	if question.qtype != 1 {
		t.Fatalf("qtype = %d", question.qtype)
	}

	response, event, err := handleQuery(query, net.ParseIP(defaultResponseIP).To4())
	if err != nil {
		t.Fatalf("handleQuery failed: %v", err)
	}
	if len(response) < 4 {
		t.Fatalf("short response: %d bytes", len(response))
	}
	if got := binary.BigEndian.Uint16(response[0:2]); got != 0x1234 {
		t.Fatalf("response id = %#x", got)
	}
	if got := binary.BigEndian.Uint16(response[6:8]); got != 1 {
		t.Fatalf("answer count = %d", got)
	}
	if got := response[len(response)-4:]; string(got) != string([]byte{198, 51, 100, 53}) {
		t.Fatalf("answer IP bytes = %v", got)
	}
	if event.Query != "f1-0.example.test" || event.QType != "A" || event.ResolvedIP == nil || *event.ResolvedIP != defaultResponseIP {
		t.Fatalf("unexpected event: %+v", event)
	}
	if len(event.CanaryMatch) != 0 || !event.Sinkholed || event.ContainerID != nil {
		t.Fatalf("unexpected event metadata: %+v", event)
	}
}

func TestEventResolvedIPMatchesConfiguredAnswer(t *testing.T) {
	query := dnsQuery(t, 0x4321, "custom.example.test", 1)
	_, event, err := handleQuery(query, net.ParseIP("203.0.113.77").To4())
	if err != nil {
		t.Fatalf("handleQuery failed: %v", err)
	}
	if event.ResolvedIP == nil || *event.ResolvedIP != "203.0.113.77" {
		t.Fatalf("resolved_ip = %#v", event.ResolvedIP)
	}
}

func TestWriteEventJSONL(t *testing.T) {
	dir := t.TempDir()
	logFile, err := openLog(filepath.Join(dir, "dns.jsonl"))
	if err != nil {
		t.Fatalf("openLog failed: %v", err)
	}
	defer logFile.Close()

	resolved := defaultResponseIP
	event := dnsEvent{
		Timestamp:   "2026-07-01T12:00:00Z",
		RunID:       "run-1",
		SampleID:    "sample-1",
		Query:       "example.test",
		QType:       "A",
		ResolvedIP:  &resolved,
		CanaryMatch: []string{},
		Sinkholed:   true,
		ContainerID: nil,
	}
	if err := writeEvent(logFile, event); err != nil {
		t.Fatalf("writeEvent failed: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "dns.jsonl"))
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json decode failed: %v", err)
	}
	if decoded["query"] != "example.test" || decoded["sinkholed"] != true {
		t.Fatalf("decoded event = %#v", decoded)
	}
	if matches, ok := decoded["canary_match"].([]any); !ok || len(matches) != 0 {
		t.Fatalf("canary_match = %#v", decoded["canary_match"])
	}
}

func dnsQuery(t *testing.T, id uint16, name string, qtype uint16) []byte {
	t.Helper()
	query := make([]byte, 12)
	binary.BigEndian.PutUint16(query[0:2], id)
	query[2] = 0x01
	query[5] = 0x01
	for _, label := range byteLabels(t, name) {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0x00, byte(qtype>>8), byte(qtype), 0x00, 0x01)
	return query
}

func byteLabels(t *testing.T, name string) [][]byte {
	t.Helper()
	parts := []string{}
	start := 0
	for i, char := range name {
		if char == '.' {
			parts = append(parts, name[start:i])
			start = i + 1
		}
	}
	parts = append(parts, name[start:])

	labels := make([][]byte, 0, len(parts))
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			t.Fatalf("invalid label %q in %q", part, name)
		}
		labels = append(labels, []byte(part))
	}
	return labels
}

package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultListenAddr = ":53"
	defaultResponseIP = "198.51.100.53"
)

type dnsQuestion struct {
	name   string
	qtype  uint16
	qclass uint16
	end    int
}

type dnsEvent struct {
	Timestamp   string   `json:"ts"`
	RunID       string   `json:"run_id"`
	SampleID    string   `json:"sample_id"`
	Query       string   `json:"query"`
	QType       string   `json:"qtype"`
	ResolvedIP  *string  `json:"resolved_ip"`
	CanaryMatch []string `json:"canary_match"`
	Sinkholed   bool     `json:"sinkholed"`
	ContainerID *string  `json:"container_id"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "dns-sinkhole: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	listenAddr := getenvDefault("EXFIL_DNS_LISTEN", defaultListenAddr)
	responseIPText := getenvDefault("EXFIL_DNS_RESPONSE_IP", defaultResponseIP)
	responseIP := net.ParseIP(responseIPText).To4()
	if responseIP == nil {
		return fmt.Errorf("EXFIL_DNS_RESPONSE_IP must be IPv4: %s", responseIPText)
	}

	logPath := getenvDefault("EXFIL_DNS_LOG", "/logs/dns.jsonl")
	logFile, err := openLog(logPath)
	if err != nil {
		return err
	}
	defer logFile.Close()

	packetConn, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return err
	}
	defer packetConn.Close()

	buf := make([]byte, 1500)
	for {
		n, addr, err := packetConn.ReadFrom(buf)
		if err != nil {
			return err
		}
		query := append([]byte(nil), buf[:n]...)
		response, event, err := handleQuery(query, responseIP)
		if err != nil {
			continue
		}
		event.RunID = getenvDefault("EXFIL_RUN_ID", "unknown-run")
		event.SampleID = getenvDefault("EXFIL_SAMPLE_ID", "unknown-sample")
		if err := writeEvent(logFile, event); err != nil {
			return err
		}
		if len(response) > 0 {
			if _, err := packetConn.WriteTo(response, addr); err != nil {
				return err
			}
		}
	}
}

func getenvDefault(name, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}

func openLog(path string) (*os.File, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}

func handleQuery(query []byte, responseIP net.IP) ([]byte, dnsEvent, error) {
	// ref: /home/mrg/Desktop/exfil-step-a-refs/flare-fakenet-ng/fakenet/listeners/DNSListener.py:101
	// Pattern: parse request bytes, extract qname/qtype, then return a fake DNS answer.
	question, err := parseQuestion(query)
	if err != nil {
		return nil, dnsEvent{}, err
	}

	resolved := responseIP.String()
	response, err := buildResponse(query, question, responseIP)
	if err != nil {
		return nil, dnsEvent{}, err
	}
	if question.qtype != 1 {
		resolved = ""
	}

	var resolvedPtr *string
	if resolved != "" {
		resolvedPtr = &resolved
	}
	event := dnsEvent{
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
		Query:       question.name,
		QType:       qtypeName(question.qtype),
		ResolvedIP:  resolvedPtr,
		CanaryMatch: []string{},
		Sinkholed:   true,
		ContainerID: nil,
	}
	return response, event, nil
}

func parseQuestion(packet []byte) (dnsQuestion, error) {
	if len(packet) < 12 {
		return dnsQuestion{}, errors.New("short DNS packet")
	}
	qdcount := binary.BigEndian.Uint16(packet[4:6])
	if qdcount == 0 {
		return dnsQuestion{}, errors.New("DNS packet has no questions")
	}

	offset := 12
	labels := []string{}
	for {
		if offset >= len(packet) {
			return dnsQuestion{}, errors.New("truncated qname")
		}
		length := int(packet[offset])
		offset++
		if length == 0 {
			break
		}
		if length&0xc0 != 0 {
			return dnsQuestion{}, errors.New("compressed qname is not supported in questions")
		}
		if length > 63 || offset+length > len(packet) {
			return dnsQuestion{}, errors.New("invalid qname label")
		}
		labels = append(labels, string(packet[offset:offset+length]))
		offset += length
	}
	if offset+4 > len(packet) {
		return dnsQuestion{}, errors.New("truncated question trailer")
	}
	name := strings.Join(labels, ".")
	if name == "" {
		name = "."
	}
	return dnsQuestion{
		name:   name,
		qtype:  binary.BigEndian.Uint16(packet[offset : offset+2]),
		qclass: binary.BigEndian.Uint16(packet[offset+2 : offset+4]),
		end:    offset + 4,
	}, nil
}

func buildResponse(query []byte, question dnsQuestion, responseIP net.IP) ([]byte, error) {
	if len(query) < question.end {
		return nil, errors.New("question end exceeds packet length")
	}

	response := make([]byte, 0, question.end+16)
	response = append(response, query[:question.end]...)
	response[2] = 0x81
	response[3] = 0x80
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[6:8], 0)
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], 0)

	if question.qtype == 1 && question.qclass == 1 {
		binary.BigEndian.PutUint16(response[6:8], 1)
		answer := []byte{
			0xc0, 0x0c,
			0x00, 0x01,
			0x00, 0x01,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x04,
			responseIP[0], responseIP[1], responseIP[2], responseIP[3],
		}
		response = append(response, answer...)
	}

	return response, nil
}

func qtypeName(qtype uint16) string {
	switch qtype {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	default:
		return fmt.Sprintf("TYPE%d", qtype)
	}
}

func writeEvent(logFile *os.File, event dnsEvent) error {
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if _, err := logFile.Write(append(encoded, '\n')); err != nil {
		return err
	}
	return logFile.Sync()
}

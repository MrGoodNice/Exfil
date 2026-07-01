# F1 Ref Ledger

- FakeNet DNS query/response pattern:
  `/home/mrg/Desktop/exfil-step-a-refs/flare-fakenet-ng/fakenet/listeners/DNSListener.py:101`
  parses DNS bytes, extracts qname/qtype, and builds a custom response.
- FakeNet fake A response:
  `/home/mrg/Desktop/exfil-step-a-refs/flare-fakenet-ng/fakenet/listeners/DNSListener.py:144`
  creates a response and
  `/home/mrg/Desktop/exfil-step-a-refs/flare-fakenet-ng/fakenet/listeners/DNSListener.py:203`
  attaches the configured fake record.
- FakeNet UDP serving pattern:
  `/home/mrg/Desktop/exfil-step-a-refs/flare-fakenet-ng/fakenet/listeners/DNSListener.py:229`
  handles UDP DNS packets and sends the response back to the client.
- FakeNet HTTP custom response pattern:
  `/home/mrg/Desktop/exfil-step-a-refs/flare-fakenet-ng/fakenet/listeners/HTTPListener.py:63`
  models host/URI-selected custom responses, and
  `/home/mrg/Desktop/exfil-step-a-refs/flare-fakenet-ng/fakenet/listeners/HTTPListener.py:288`
  uses request host/path before returning a synthetic response.
- FakeNet HTTP request logging pattern:
  `/home/mrg/Desktop/exfil-step-a-refs/flare-fakenet-ng/fakenet/listeners/HTTPListener.py:315`
  logs GET requests, and
  `/home/mrg/Desktop/exfil-step-a-refs/flare-fakenet-ng/fakenet/listeners/HTTPListener.py:337`
  reads POST bodies before responding.
- mitmproxy CA generation pattern:
  `/home/mrg/Desktop/exfil-step-a-refs/mitmproxy/mitmproxy/certs.py:232`
  generates a CA private key and CA certificate, and
  `/home/mrg/Desktop/exfil-step-a-refs/mitmproxy/mitmproxy/certs.py:314`
  mints leaf certificates for requested SAN/common-name values.
- mitmproxy certificate cache pattern:
  `/home/mrg/Desktop/exfil-step-a-refs/mitmproxy/mitmproxy/certs.py:681`
  fetches or creates a matching certificate for a connection.
- mitmproxy original-destination note:
  `/home/mrg/Desktop/exfil-step-a-refs/mitmproxy/mitmproxy/platform/linux.py:9`
  recovers `SO_ORIGINAL_DST` for transparent redirects. F1.2a does not use
  this because DNS routes targets directly to the honeynet listener IP.
- Go TLS API checked locally:
  `go doc crypto/tls Config.GetCertificate`, `go doc crypto/x509 CreateCertificate`,
  `go doc net/http Server.ListenAndServeTLS`, and `go doc crypto/x509 SystemCertPool`.
- Go connection/flow API checked locally:
  `go doc net/http Server.ConnContext`, `go doc context.WithValue`,
  `go doc net Conn.RemoteAddr`, `go doc net Conn.LocalAddr`,
  `go doc net.Listen`, `go doc net/http Server.Serve`,
  `go doc net/http Server.ServeTLS`, `go doc crypto/tls Server`,
  `go doc crypto/tls ClientHelloInfo.Context`, `go doc net.SplitHostPort`,
  and `go doc strconv.Atoi`.
- Go canary matching API checked locally:
  `go doc os.ReadFile`, `go doc encoding/json.Unmarshal`,
  `go doc strings.Contains`, `go doc strings.ReplaceAll`,
  and `go doc net/http Request.Header`.
- Docker F1 network pattern:
  `docker network create --help` on local Docker 29.6.0 confirms `--internal`
  and `--label`; `docker run --help` confirms `--network` and `--dns`.
- Deliberately not borrowed:
  FakeNet Diverter and host traffic redirection. F1 uses only a Docker
  `--internal` network plus explicit container DNS.

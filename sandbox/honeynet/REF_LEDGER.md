# F1.0 Ref Ledger

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
- Docker F1.0 network pattern:
  `docker network create --help` on local Docker 29.6.0 confirms `--internal`
  and `--label`; `docker run --help` confirms `--network` and `--dns`.
- Deliberately not borrowed:
  FakeNet Diverter and host traffic redirection. F1.0 uses only a Docker
  `--internal` network plus explicit container DNS.

package com.exfilanalyzer.ingest;

import java.util.List;

public record RunEvents(
        List<NetworkEvent> network,
        List<DnsEvent> dns,
        List<HttpEvent> http,
        List<FileEvent> files,
        List<ProcEvent> proc,
        List<JsonlParseError> parseErrors) {
    public RunEvents {
        network = List.copyOf(network);
        dns = List.copyOf(dns);
        http = List.copyOf(http);
        files = List.copyOf(files);
        proc = List.copyOf(proc);
        parseErrors = List.copyOf(parseErrors);
    }
}

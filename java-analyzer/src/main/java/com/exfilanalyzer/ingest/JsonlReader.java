package com.exfilanalyzer.ingest;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class JsonlReader {
    private final ObjectMapper mapper;

    public JsonlReader() {
        this(new ObjectMapper());
    }

    JsonlReader(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public RunEvents readRun(Path runDir) throws IOException {
        List<JsonlParseError> errors = new ArrayList<>();
        List<NetworkEvent> network = readStream(runDir, "network.jsonl", NetworkEvent.class, errors);
        List<DnsEvent> dns = readStream(runDir, "dns.jsonl", DnsEvent.class, errors);
        List<HttpEvent> http = readStream(runDir, "http.jsonl", HttpEvent.class, errors);
        List<FileEvent> files = readStream(runDir, "files.jsonl", FileEvent.class, errors);
        List<ProcEvent> proc = readStream(runDir, "proc.jsonl", ProcEvent.class, errors);
        return new RunEvents(network, dns, http, files, proc, errors);
    }

    private <T> List<T> readStream(
            Path runDir, String fileName, Class<T> eventClass, List<JsonlParseError> errors)
            throws IOException {
        Path path = runDir.resolve(fileName);
        if (!Files.exists(path)) {
            return List.of();
        }

        List<T> events = new ArrayList<>();
        try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            String line;
            int lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                if (line.isBlank()) {
                    continue;
                }
                try {
                    events.add(mapper.readValue(line, eventClass));
                } catch (IOException ex) {
                    errors.add(new JsonlParseError(fileName, lineNumber, ex.getMessage(), line));
                }
            }
        }
        return List.copyOf(events);
    }
}

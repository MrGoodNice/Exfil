package com.exfilanalyzer.ingest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class JsonlReaderTest {
    @TempDir
    Path tempDir;

    @Test
    void readsValidLinesAndCollectsBadLineWithoutDroppingWholeRun() throws Exception {
        Files.writeString(
                tempDir.resolve("network.jsonl"),
                """
                {"ts":"2026-07-02T10:00:01Z","run_id":"run-a","sample_id":"sample-a","source":"aya_connect","flow_id":null,"pid":101,"src_ip":null,"src_port":null,"dst_ip":"203.0.113.10","dst_port":443,"proto":"tcp","retval":-101,"container_id":"ctr-a","cgroup_id":"42"}
                { this is not json }
                {"ts":"2026-07-02T10:00:02Z","run_id":"run-a","sample_id":"sample-a","source":"honeynet","flow_id":"flow-a","pid":null,"src_ip":"172.18.0.2","src_port":44100,"dst_ip":"203.0.113.10","dst_port":443,"proto":"tcp","retval":null,"container_id":"ctr-a","cgroup_id":"42"}
                """);

        RunEvents events = new JsonlReader().readRun(tempDir);

        assertEquals(2, events.network().size());
        assertEquals(1, events.parseErrors().size());
        JsonlParseError error = events.parseErrors().getFirst();
        assertEquals("network.jsonl", error.fileName());
        assertEquals(2, error.line());
        assertTrue(error.message().contains("Unexpected character") || error.message().contains("was expecting"));
        assertEquals("203.0.113.10", events.network().getFirst().dstIp());
    }

    @Test
    void missingStreamsAreEmptyRatherThanFatal() throws Exception {
        Files.writeString(
                tempDir.resolve("files.jsonl"),
                """
                {"ts":"2026-07-02T10:00:00Z","run_id":"run-a","sample_id":"sample-a","pid":100,"tgid":100,"comm":"cat","path":"/canary/canary_rsa","is_canary":true,"container_id":"ctr-a","cgroup_id":"42"}
                """);

        RunEvents events = new JsonlReader().readRun(tempDir);

        assertEquals(1, events.files().size());
        assertTrue(events.network().isEmpty());
        assertTrue(events.dns().isEmpty());
        assertTrue(events.http().isEmpty());
        assertTrue(events.proc().isEmpty());
        assertTrue(events.parseErrors().isEmpty());
    }

    @Test
    void readsAllFiveTypedStreams() throws Exception {
        Files.writeString(
                tempDir.resolve("network.jsonl"),
                """
                {"ts":"2026-07-02T10:00:01Z","run_id":"run-a","sample_id":"sample-a","source":"honeynet","flow_id":"flow-a","pid":null,"src_ip":"172.18.0.2","src_port":44100,"dst_ip":"203.0.113.10","dst_port":443,"proto":"tcp","retval":null,"container_id":"ctr-a","cgroup_id":"42"}
                """);
        Files.writeString(
                tempDir.resolve("dns.jsonl"),
                """
                {"ts":"2026-07-02T10:00:00Z","run_id":"run-a","sample_id":"sample-a","query":"evil.example.test","qtype":"A","resolved_ip":"172.18.0.10","canary_match":["dns-canary"],"sinkholed":true,"container_id":"ctr-a"}
                """);
        Files.writeString(
                tempDir.resolve("http.jsonl"),
                """
                {"ts":"2026-07-02T10:00:02Z","run_id":"run-a","sample_id":"sample-a","flow_id":"flow-a","method":"POST","host":"evil.example.test","path":"/exfil","tls":true,"opaque_reason":null,"canary_match":["body-canary"],"request_body_sha256":"aaa","response_body_sha256":"bbb","upstream":false}
                """);
        Files.writeString(
                tempDir.resolve("files.jsonl"),
                """
                {"ts":"2026-07-02T10:00:00Z","run_id":"run-a","sample_id":"sample-a","pid":100,"tgid":100,"comm":"cat","path":"/canary/canary_rsa","is_canary":true,"container_id":"ctr-a","cgroup_id":"42"}
                """);
        Files.writeString(
                tempDir.resolve("proc.jsonl"),
                """
                {"ts":"2026-07-02T09:59:59Z","run_id":"run-a","sample_id":"sample-a","pid":100,"ppid":1,"tgid":100,"comm":"cat","exe":"/bin/cat","exe_hash":"hash100","event":"execve","container_id":"ctr-a","cgroup_id":"42"}
                """);

        RunEvents events = new JsonlReader().readRun(tempDir);

        assertEquals(1, events.network().size());
        assertEquals(1, events.dns().size());
        assertEquals(1, events.http().size());
        assertEquals(1, events.files().size());
        assertEquals(1, events.proc().size());
        assertEquals(List.of("dns-canary"), events.dns().getFirst().canaryMatch());
        assertEquals(List.of("body-canary"), events.http().getFirst().canaryMatch());
        assertTrue(events.parseErrors().isEmpty());
    }
}

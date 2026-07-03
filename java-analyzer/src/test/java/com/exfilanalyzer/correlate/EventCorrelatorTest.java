package com.exfilanalyzer.correlate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.exfilanalyzer.ingest.JsonlReader;
import com.exfilanalyzer.ingest.RunEvents;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class EventCorrelatorTest {
    @TempDir
    Path tempDir;

    @Test
    void maliciousDirectProducesOneJoinedEgressWithPidHostAndCanaryMatch() throws Exception {
        writeDirectScenario(tempDir, "run-direct");

        CorrelatedRun run = onlyRun(correlate(tempDir));

        assertEquals("run-direct", run.runId());
        assertEquals(1, run.egressEvents().size(), "honeynet and aya_connect must not double-count");
        EgressEvent egress = run.egressEvents().getFirst();
        assertEquals("203.0.113.10", egress.dstIp());
        assertEquals(443, egress.dstPort());
        assertEquals("tcp", egress.proto());
        assertEquals(100, egress.pid());
        assertEquals("evil.example.test", egress.host());
        assertEquals("/exfil", egress.path());
        assertEquals(List.of("canary-rsa-1"), egress.canaryMatch());
        assertTrue(egress.joined());
        assertTrue(run.touchedCanaryPaths().contains("/canary/canary_rsa"));
        assertTrue(run.matchedCanaryIds().contains("canary-rsa-1"));
        assertEquals(1, run.evidenceChains().size());
        EvidenceChain chain = run.evidenceChains().getFirst();
        assertEquals(100, chain.filePid());
        assertEquals(100, chain.egressPid());
        assertEquals(List.of(100), chain.processPath());
        assertEquals("/canary/canary_rsa", chain.canaryPath());
    }

    @Test
    void maliciousChildAttributesEgressToChildAndLinksParentProcessTree() throws Exception {
        writeChildScenario(tempDir, "run-child");

        CorrelatedRun run = onlyRun(correlate(tempDir));

        assertEquals(1, run.egressEvents().size());
        EgressEvent egress = run.egressEvents().getFirst();
        assertEquals(201, egress.pid());
        assertEquals("evil-child.example.test", egress.host());
        assertEquals(List.of("canary-rsa-child"), egress.canaryMatch());
        assertEquals(1, run.evidenceChains().size());
        EvidenceChain chain = run.evidenceChains().getFirst();
        assertEquals(200, chain.filePid());
        assertEquals(201, chain.egressPid());
        assertEquals(List.of(200, 201), chain.processPath());
    }

    @Test
    void unmatchedAyaConnectBecomesNetworkOnlyEgress() throws Exception {
        Files.writeString(
                tempDir.resolve("network.jsonl"),
                """
                {"ts":"2026-07-02T10:00:01Z","run_id":"run-raw","sample_id":"sample-a","source":"aya_connect","flow_id":null,"pid":333,"src_ip":null,"src_port":null,"dst_ip":"198.51.100.55","dst_port":4444,"proto":"tcp","retval":-101,"container_id":"ctr-a","cgroup_id":"42"}
                """);

        CorrelatedRun run = onlyRun(correlate(tempDir));

        assertEquals(1, run.egressEvents().size());
        EgressEvent egress = run.egressEvents().getFirst();
        assertEquals(333, egress.pid());
        assertEquals("198.51.100.55", egress.dstIp());
        assertNull(egress.host());
        assertTrue(egress.networkOnly());
        assertTrue(egress.canaryMatch().isEmpty());
    }

    @Test
    void rawIpAfterCanaryReadKeepsAttemptEvidenceWithoutPayloadConfirmation() throws Exception {
        writeRawIpAttemptScenario(tempDir, "run-raw-attempt");

        CorrelatedRun run = onlyRun(correlate(tempDir));

        assertEquals(1, run.egressEvents().size());
        EgressEvent egress = run.egressEvents().getFirst();
        assertTrue(egress.networkOnly());
        assertEquals("198.51.100.10", egress.dstIp());
        assertTrue(egress.canaryMatch().isEmpty(), "raw-IP payload is not L7-visible in DNS-steered honeynet");
        assertTrue(run.matchedCanaryIds().isEmpty(), "attempted raw-IP egress must not be exfil-confirmed");
        assertEquals(1, run.evidenceChains().size());
        EvidenceChain chain = run.evidenceChains().getFirst();
        assertEquals(300, chain.filePid());
        assertEquals(301, chain.egressPid());
        assertEquals(List.of(300, 301), chain.processPath());
        assertTrue(chain.canaryMatch().isEmpty());
    }

    @Test
    void unmatchedHoneynetFlowIsKeptWithNullPid() throws Exception {
        Files.writeString(
                tempDir.resolve("network.jsonl"),
                """
                {"ts":"2026-07-02T10:00:02Z","run_id":"run-honeynet","sample_id":"sample-a","source":"honeynet","flow_id":"flow-h","pid":null,"src_ip":"172.18.0.2","src_port":44100,"dst_ip":"203.0.113.99","dst_port":80,"proto":"tcp","retval":null,"container_id":"ctr-a","cgroup_id":"42"}
                """);
        Files.writeString(
                tempDir.resolve("http.jsonl"),
                """
                {"ts":"2026-07-02T10:00:02Z","run_id":"run-honeynet","sample_id":"sample-a","flow_id":"flow-h","method":"GET","host":"only-honeynet.example.test","path":"/stage","tls":false,"opaque_reason":null,"canary_match":[],"request_body_sha256":null,"response_body_sha256":"abc","upstream":false}
                """);

        CorrelatedRun run = onlyRun(correlate(tempDir));

        assertEquals(1, run.egressEvents().size());
        EgressEvent egress = run.egressEvents().getFirst();
        assertNull(egress.pid());
        assertEquals("only-honeynet.example.test", egress.host());
        assertEquals("/stage", egress.path());
        assertTrue(egress.honeynetOnly());
    }

    @Test
    void eventsAreGroupedByRunIdBeforeJoining() throws Exception {
        Files.writeString(
                tempDir.resolve("network.jsonl"),
                """
                {"ts":"2026-07-02T10:00:01Z","run_id":"run-a","sample_id":"sample-a","source":"aya_connect","flow_id":null,"pid":401,"src_ip":null,"src_port":null,"dst_ip":"203.0.113.77","dst_port":443,"proto":"tcp","retval":-101,"container_id":"ctr-a","cgroup_id":"42"}
                {"ts":"2026-07-02T10:00:02Z","run_id":"run-b","sample_id":"sample-b","source":"honeynet","flow_id":"flow-b","pid":null,"src_ip":"172.18.0.2","src_port":44100,"dst_ip":"203.0.113.77","dst_port":443,"proto":"tcp","retval":null,"container_id":"ctr-b","cgroup_id":"84"}
                """);
        Files.writeString(
                tempDir.resolve("http.jsonl"),
                """
                {"ts":"2026-07-02T10:00:02Z","run_id":"run-b","sample_id":"sample-b","flow_id":"flow-b","method":"POST","host":"run-b.example.test","path":"/exfil","tls":true,"opaque_reason":null,"canary_match":["run-b-canary"],"request_body_sha256":"aaa","response_body_sha256":"bbb","upstream":false}
                """);

        AnalysisResult result = correlate(tempDir);

        assertEquals(2, result.runs().size());
        CorrelatedRun runA = result.runs().stream()
                .filter(run -> run.runId().equals("run-a"))
                .findFirst()
                .orElseThrow();
        CorrelatedRun runB = result.runs().stream()
                .filter(run -> run.runId().equals("run-b"))
                .findFirst()
                .orElseThrow();
        assertEquals(1, runA.egressEvents().size());
        assertTrue(runA.egressEvents().getFirst().networkOnly());
        assertEquals(401, runA.egressEvents().getFirst().pid());
        assertEquals(1, runB.egressEvents().size());
        assertTrue(runB.egressEvents().getFirst().honeynetOnly());
        assertNull(runB.egressEvents().getFirst().pid());
    }

    private static AnalysisResult correlate(Path runDir) throws Exception {
        RunEvents events = new JsonlReader().readRun(runDir);
        assertTrue(events.parseErrors().isEmpty(), () -> "fixture parse errors: " + events.parseErrors());
        return new EventCorrelator().correlate(events);
    }

    private static CorrelatedRun onlyRun(AnalysisResult result) {
        assertEquals(1, result.runs().size());
        return result.runs().getFirst();
    }

    private static void writeDirectScenario(Path dir, String runId) throws Exception {
        Files.writeString(
                dir.resolve("network.jsonl"),
                """
                {"ts":"2026-07-02T10:00:01Z","run_id":"%s","sample_id":"sample-a","source":"aya_connect","flow_id":null,"pid":100,"src_ip":null,"src_port":null,"dst_ip":"203.0.113.10","dst_port":443,"proto":"tcp","retval":-101,"container_id":"ctr-a","cgroup_id":"42"}
                {"ts":"2026-07-02T10:00:02Z","run_id":"%s","sample_id":"sample-a","source":"honeynet","flow_id":"flow-direct","pid":null,"src_ip":"172.18.0.2","src_port":44100,"dst_ip":"203.0.113.10","dst_port":443,"proto":"tcp","retval":null,"container_id":"ctr-a","cgroup_id":"42"}
                """.formatted(runId, runId));
        Files.writeString(
                dir.resolve("http.jsonl"),
                """
                {"ts":"2026-07-02T10:00:02Z","run_id":"%s","sample_id":"sample-a","flow_id":"flow-direct","method":"POST","host":"evil.example.test","path":"/exfil","tls":true,"opaque_reason":null,"canary_match":["canary-rsa-1"],"request_body_sha256":"aaa","response_body_sha256":"bbb","upstream":false}
                """.formatted(runId));
        Files.writeString(
                dir.resolve("files.jsonl"),
                """
                {"ts":"2026-07-02T10:00:00Z","run_id":"%s","sample_id":"sample-a","pid":100,"tgid":100,"comm":"curl","path":"/canary/canary_rsa","is_canary":true,"container_id":"ctr-a","cgroup_id":"42"}
                """.formatted(runId));
        Files.writeString(
                dir.resolve("proc.jsonl"),
                """
                {"ts":"2026-07-02T09:59:59Z","run_id":"%s","sample_id":"sample-a","pid":100,"ppid":1,"tgid":100,"comm":"curl","exe":"/usr/bin/curl","argv_hash":"hash100","event":"execve","container_id":"ctr-a","cgroup_id":"42"}
                """.formatted(runId));
        Files.writeString(dir.resolve("dns.jsonl"), "");
    }

    private static void writeChildScenario(Path dir, String runId) throws Exception {
        Files.writeString(
                dir.resolve("network.jsonl"),
                """
                {"ts":"2026-07-02T10:00:02Z","run_id":"%s","sample_id":"sample-a","source":"aya_connect","flow_id":null,"pid":201,"src_ip":null,"src_port":null,"dst_ip":"203.0.113.20","dst_port":443,"proto":"tcp","retval":-101,"container_id":"ctr-a","cgroup_id":"42"}
                {"ts":"2026-07-02T10:00:03Z","run_id":"%s","sample_id":"sample-a","source":"honeynet","flow_id":"flow-child","pid":null,"src_ip":"172.18.0.2","src_port":44101,"dst_ip":"203.0.113.20","dst_port":443,"proto":"tcp","retval":null,"container_id":"ctr-a","cgroup_id":"42"}
                """.formatted(runId, runId));
        Files.writeString(
                dir.resolve("http.jsonl"),
                """
                {"ts":"2026-07-02T10:00:03Z","run_id":"%s","sample_id":"sample-a","flow_id":"flow-child","method":"POST","host":"evil-child.example.test","path":"/child","tls":true,"opaque_reason":null,"canary_match":["canary-rsa-child"],"request_body_sha256":"ccc","response_body_sha256":"ddd","upstream":false}
                """.formatted(runId));
        Files.writeString(
                dir.resolve("files.jsonl"),
                """
                {"ts":"2026-07-02T10:00:00Z","run_id":"%s","sample_id":"sample-a","pid":200,"tgid":200,"comm":"sh","path":"/canary/canary_rsa","is_canary":true,"container_id":"ctr-a","cgroup_id":"42"}
                """.formatted(runId));
        Files.writeString(
                dir.resolve("proc.jsonl"),
                """
                {"ts":"2026-07-02T09:59:59Z","run_id":"%s","sample_id":"sample-a","pid":200,"ppid":1,"tgid":200,"comm":"sh","exe":"/bin/sh","argv_hash":"hash200","event":"execve","container_id":"ctr-a","cgroup_id":"42"}
                {"ts":"2026-07-02T10:00:01Z","run_id":"%s","sample_id":"sample-a","pid":201,"ppid":200,"tgid":201,"comm":"curl","exe":"/usr/bin/curl","argv_hash":"hash201","event":"execve","container_id":"ctr-a","cgroup_id":"42"}
                """.formatted(runId, runId));
        Files.writeString(dir.resolve("dns.jsonl"), "");
    }

    private static void writeRawIpAttemptScenario(Path dir, String runId) throws Exception {
        Files.writeString(
                dir.resolve("network.jsonl"),
                """
                {"ts":"2026-07-02T10:00:03Z","run_id":"%s","sample_id":"sample-a","source":"aya_connect","flow_id":null,"pid":301,"src_ip":null,"src_port":null,"dst_ip":"198.51.100.10","dst_port":80,"proto":"tcp","retval":-101,"container_id":"ctr-a","cgroup_id":"42"}
                """.formatted(runId));
        Files.writeString(
                dir.resolve("files.jsonl"),
                """
                {"ts":"2026-07-02T10:00:00Z","run_id":"%s","sample_id":"sample-a","pid":300,"tgid":300,"comm":"sh","path":"/canary/canary_rsa","is_canary":true,"container_id":"ctr-a","cgroup_id":"42"}
                """.formatted(runId));
        Files.writeString(
                dir.resolve("proc.jsonl"),
                """
                {"ts":"2026-07-02T09:59:59Z","run_id":"%s","sample_id":"sample-a","pid":300,"ppid":1,"tgid":300,"comm":"sh","exe":"/bin/sh","argv_hash":"hash300","event":"execve","container_id":"ctr-a","cgroup_id":"42"}
                {"ts":"2026-07-02T10:00:02Z","run_id":"%s","sample_id":"sample-a","pid":301,"ppid":300,"tgid":301,"comm":"wget","exe":"/bin/wget","argv_hash":"hash301","event":"execve","container_id":"ctr-a","cgroup_id":"42"}
                """.formatted(runId, runId));
        Files.writeString(dir.resolve("http.jsonl"), "");
        Files.writeString(dir.resolve("dns.jsonl"), "");
    }
}

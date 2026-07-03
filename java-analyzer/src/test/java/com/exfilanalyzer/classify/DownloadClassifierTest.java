package com.exfilanalyzer.classify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.exfilanalyzer.correlate.CorrelatedRun;
import com.exfilanalyzer.correlate.EgressEvent;
import com.exfilanalyzer.ingest.DnsEvent;
import com.exfilanalyzer.ingest.HttpEvent;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

final class DownloadClassifierTest {
    private final DownloadClassifier classifier = DownloadClassifier.loadDefault();

    @Test
    void canaryMatchIsExfilConfirmedWithHighestPriority() {
        EgressEvent egress = egress("203.0.113.10", "evil.example.test", "flow-1", List.of("canary-rsa"));
        ClassifiedEgress classified = only(classifier.classify(run(egress), httpWithBody(egress), List.of()));

        assertEquals(Disposition.EXFIL_CONFIRMED, classified.disposition());
        assertTrue(classified.reasons().contains("canary_match"));
        assertEquals(DownloadState.OBSERVED, classified.downloadState());
    }

    @Test
    void rawIpDestinationIsSuspiciousAndAttemptedWhenNoHttpBody() {
        EgressEvent egress = egress("198.51.100.10", null, null, List.of());
        ClassifiedEgress classified = only(classifier.classify(run(egress), List.of(), List.of()));

        assertEquals(Disposition.SUSPICIOUS, classified.disposition());
        assertTrue(classified.reasons().contains("raw_ip"));
        assertEquals(DownloadState.ATTEMPTED, classified.downloadState());
    }

    @Test
    void guarddogEphemeralDomainIsSuspicious() {
        EgressEvent egress = egress("203.0.113.11", "hook.webhook.site", "flow-2", List.of());
        ClassifiedEgress classified = only(classifier.classify(run(egress), httpWithoutBody(egress), List.of()));

        assertEquals(Disposition.SUSPICIOUS, classified.disposition());
        assertTrue(classified.reasons().contains("ephemeral_domain"));
        assertEquals(DownloadState.ATTEMPTED, classified.downloadState());
    }

    @Test
    void guarddogUrlShortenerIsSuspicious() {
        EgressEvent egress = egress("203.0.113.15", "bit.ly", "flow-short", List.of());
        ClassifiedEgress classified = only(classifier.classify(run(egress), httpWithoutBody(egress), List.of()));

        assertEquals(Disposition.SUSPICIOUS, classified.disposition());
        assertTrue(classified.reasons().contains("url_shortener"));
    }

    @Test
    void guarddogExfilServicePathIsSuspicious() {
        EgressEvent egress = new EgressEvent(
                "run-a",
                "sample-a",
                "2026-07-02T10:00:00Z",
                "203.0.113.16",
                443,
                "tcp",
                100,
                "discord.com",
                "/api/webhooks/123/secret",
                List.of(),
                "flow-discord",
                true,
                false,
                false);
        ClassifiedEgress classified = only(classifier.classify(run(egress), httpWithoutBody(egress), List.of()));

        assertEquals(Disposition.SUSPICIOUS, classified.disposition());
        assertTrue(classified.reasons().contains("exfil_service"));
    }

    @Test
    void guarddogIntelLookupServiceIsSuspicious() {
        EgressEvent egress = egress("203.0.113.17", "ipinfo.io", "flow-intel", List.of());
        ClassifiedEgress classified = only(classifier.classify(run(egress), httpWithoutBody(egress), List.of()));

        assertEquals(Disposition.SUSPICIOUS, classified.disposition());
        assertTrue(classified.reasons().contains("intel_lookup"));
    }

    @Test
    void guarddogMalwareDownloadServiceIsSuspicious() {
        EgressEvent egress = egress("203.0.113.18", "files.catbox.moe", "flow-catbox", List.of());
        ClassifiedEgress classified = only(classifier.classify(run(egress), httpWithoutBody(egress), List.of()));

        assertEquals(Disposition.SUSPICIOUS, classified.disposition());
        assertTrue(classified.reasons().contains("malware_download"));
    }

    @Test
    void dnsCanaryMatchConfirmsDnsExfilForMatchingHost() {
        EgressEvent egress = egress("203.0.113.12", "token.evil.example.test", "flow-3", List.of());
        DnsEvent dns = new DnsEvent(
                "2026-07-02T10:00:00Z",
                "run-a",
                "sample-a",
                "token.evil.example.test",
                "A",
                "172.18.0.10",
                List.of("canary-dns"),
                true,
                "ctr-a");

        ClassifiedEgress classified = only(classifier.classify(run(egress), List.of(), List.of(dns)));

        assertEquals(Disposition.EXFIL_CONFIRMED, classified.disposition());
        assertTrue(classified.reasons().contains("dns_exfil"));
        assertTrue(classified.reasons().contains("dns_canary_match"));
    }

    @Test
    void ordinaryDomainWithObservedBodyIsLegitLooking() {
        EgressEvent egress = egress("203.0.113.13", "registry.npmjs.org", "flow-4", List.of());
        ClassifiedEgress classified = only(classifier.classify(run(egress), httpWithBody(egress), List.of()));

        assertEquals(Disposition.LEGIT_LOOKING, classified.disposition());
        assertTrue(classified.reasons().contains("no_suspicious_signals"));
        assertEquals(DownloadState.OBSERVED, classified.downloadState());
        assertTrue(classified.reasons().contains("synthetic_honeynet_response"));
    }

    @Test
    void unknownDestinationIsSuspiciousNotLegit() {
        EgressEvent egress = new EgressEvent(
                "run-a",
                "sample-a",
                "2026-07-02T10:00:00Z",
                "not-an-ip",
                443,
                "tcp",
                100,
                null,
                null,
                List.of(),
                null,
                false,
                true,
                false);

        ClassifiedEgress classified = only(classifier.classify(run(egress), List.of(), List.of()));

        assertEquals(Disposition.SUSPICIOUS, classified.disposition());
        assertTrue(classified.reasons().contains("unknown_destination"));
    }

    @Test
    void highEntropyDomainIsSuspicious() {
        EgressEvent egress = egress("203.0.113.14", "x9q2m7z4k1p8d3a6.example.test", "flow-5", List.of());
        ClassifiedEgress classified = only(classifier.classify(run(egress), httpWithoutBody(egress), List.of()));

        assertEquals(Disposition.SUSPICIOUS, classified.disposition());
        assertTrue(classified.reasons().contains("high_entropy_domain"));
    }

    @Test
    void constructedDnsSubdomainWithoutCanaryIsSuspiciousNotConfirmed() {
        EgressEvent egress = egress("203.0.113.19", "aaaabbbbccccddddeeeeffff.example.test", "flow-dns", List.of());
        DnsEvent dns = new DnsEvent(
                "2026-07-02T10:00:00Z",
                "run-a",
                "sample-a",
                "aaaabbbbccccddddeeeeffff.example.test",
                "A",
                "172.18.0.10",
                List.of(),
                true,
                "ctr-a");

        ClassifiedEgress classified = only(classifier.classify(run(egress), List.of(), List.of(dns)));

        assertEquals(Disposition.SUSPICIOUS, classified.disposition());
        assertTrue(classified.reasons().contains("dns_exfil"));
    }

    @Test
    void defaultGuarddogDataContainsReviewedDomains() {
        assertTrue(classifier.isListedDomain("webhook.site"));
        assertTrue(classifier.isListedDomain("ngrok.io"));
        assertTrue(classifier.isListedDomain("bit.ly"));
    }

    private static ClassifiedEgress only(ClassificationResult result) {
        assertEquals(1, result.egress().size());
        return result.egress().getFirst();
    }

    private static CorrelatedRun run(EgressEvent egress) {
        return new CorrelatedRun(
                "run-a",
                List.of(egress),
                List.of(),
                Set.of(),
                Set.copyOf(egress.canaryMatch()));
    }

    private static EgressEvent egress(String dstIp, String host, String flowId, List<String> canaryMatch) {
        return new EgressEvent(
                "run-a",
                "sample-a",
                "2026-07-02T10:00:00Z",
                dstIp,
                443,
                "tcp",
                100,
                host,
                "/download",
                canaryMatch,
                flowId,
                flowId != null,
                flowId == null,
                false);
    }

    private static List<HttpEvent> httpWithBody(EgressEvent egress) {
        return List.of(http(egress, "abc123"));
    }

    private static List<HttpEvent> httpWithoutBody(EgressEvent egress) {
        return List.of(http(egress, null));
    }

    private static HttpEvent http(EgressEvent egress, String responseHash) {
        return new HttpEvent(
                egress.ts(),
                egress.runId(),
                egress.sampleId(),
                egress.flowId(),
                "GET",
                egress.host(),
                egress.path(),
                true,
                null,
                egress.canaryMatch(),
                "request-hash",
                responseHash,
                false);
    }
}

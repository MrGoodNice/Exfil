package com.exfilanalyzer.classify;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.exfilanalyzer.correlate.CorrelatedRun;
import com.exfilanalyzer.correlate.EgressEvent;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * H3 characterization: a hostile Host/SNI value must not crash classification of the whole run.
 * IDN.toASCII throws IllegalArgumentException on a label > 63 chars; URI.create throws on illegal
 * authority chars. normalizeHost() calls both on attacker-controlled input with no try/catch, so
 * one bad egress aborts the classify() stream and takes every other egress in the run with it.
 *
 * These tests encode the DESIRED post-fix behavior; they are RED against current code (they throw).
 */
final class H3HostileHostTest {
    private final DownloadClassifier classifier = DownloadClassifier.loadDefault();

    private static final String OVERLONG_LABEL = "a".repeat(64) + ".example.test";
    private static final String BAD_URI_HOST = "http://ho st/evil"; // contains "://" -> URI.create path

    @Test
    void oneOverlongLabelDoesNotCrashRun() {
        // Two egress in one run: [0] hostile 64-char label, [1] benign.
        // Pre-fix: classify() throws IllegalArgumentException and BOTH results are lost.
        EgressEvent hostile = egress("203.0.113.20", OVERLONG_LABEL);
        EgressEvent benign = egress("203.0.113.21", "registry.npmjs.org");
        CorrelatedRun run = run(hostile, benign);

        ClassificationResult result =
                assertDoesNotThrow(() -> classifier.classify(run, List.of(), List.of()));
        assertEquals(2, result.egress().size(), "one bad host must not drop the other egress");
    }

    @Test
    void hostContainingSchemeWithBadCharsDoesNotCrashRun() {
        EgressEvent hostile = egress("203.0.113.22", BAD_URI_HOST);
        CorrelatedRun run = run(hostile);

        ClassificationResult result =
                assertDoesNotThrow(() -> classifier.classify(run, List.of(), List.of()));
        assertEquals(1, result.egress().size());
    }

    @Test
    void isListedDomainSurvivesHostileHost() {
        // Public entrypoint that also flows into normalizeHost via DomainList.matches.
        assertDoesNotThrow(() -> classifier.isListedDomain(OVERLONG_LABEL));
    }

    private static CorrelatedRun run(EgressEvent... egress) {
        return new CorrelatedRun("run-a", List.of(egress), List.of(), Set.of(), Set.of());
    }

    private static EgressEvent egress(String dstIp, String host) {
        return new EgressEvent(
                "run-a",
                "sample-a",
                "2026-07-03T10:00:00Z",
                dstIp,
                443,
                "tcp",
                100,
                host,
                "/download",
                List.of(),
                "flow-" + dstIp,
                true,
                false,
                false);
    }
}

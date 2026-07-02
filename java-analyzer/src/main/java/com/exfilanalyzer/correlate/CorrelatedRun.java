package com.exfilanalyzer.correlate;

import java.util.List;
import java.util.Set;

public record CorrelatedRun(
        String runId,
        List<EgressEvent> egressEvents,
        List<EvidenceChain> evidenceChains,
        Set<String> touchedCanaryPaths,
        Set<String> matchedCanaryIds) {
    public CorrelatedRun {
        egressEvents = List.copyOf(egressEvents);
        evidenceChains = List.copyOf(evidenceChains);
        touchedCanaryPaths = Set.copyOf(touchedCanaryPaths);
        matchedCanaryIds = Set.copyOf(matchedCanaryIds);
    }
}

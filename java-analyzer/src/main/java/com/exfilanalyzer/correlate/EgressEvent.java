package com.exfilanalyzer.correlate;

import java.util.List;

public record EgressEvent(
        String runId,
        String sampleId,
        String ts,
        String dstIp,
        int dstPort,
        String proto,
        Integer pid,
        String host,
        String path,
        List<String> canaryMatch,
        String flowId,
        boolean joined,
        boolean networkOnly,
        boolean honeynetOnly) {
    public EgressEvent {
        canaryMatch = canaryMatch == null ? List.of() : List.copyOf(canaryMatch);
    }
}

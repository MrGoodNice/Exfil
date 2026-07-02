package com.exfilanalyzer.correlate;

import java.util.List;

public record EvidenceChain(
        String runId,
        int filePid,
        String canaryPath,
        Integer egressPid,
        List<Integer> processPath,
        EgressEvent egress,
        List<String> canaryMatch) {
    public EvidenceChain {
        processPath = List.copyOf(processPath);
        canaryMatch = canaryMatch == null ? List.of() : List.copyOf(canaryMatch);
    }
}

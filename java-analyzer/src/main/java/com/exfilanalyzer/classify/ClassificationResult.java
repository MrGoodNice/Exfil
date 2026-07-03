package com.exfilanalyzer.classify;

import java.util.List;

public record ClassificationResult(String runId, List<ClassifiedEgress> egress) {
    public ClassificationResult {
        egress = List.copyOf(egress);
    }
}

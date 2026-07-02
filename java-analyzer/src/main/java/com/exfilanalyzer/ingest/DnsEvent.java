package com.exfilanalyzer.ingest;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record DnsEvent(
        String ts,
        @JsonProperty("run_id") String runId,
        @JsonProperty("sample_id") String sampleId,
        String query,
        String qtype,
        @JsonProperty("resolved_ip") String resolvedIp,
        @JsonProperty("canary_match") List<String> canaryMatch,
        boolean sinkholed,
        @JsonProperty("container_id") String containerId) {
    public DnsEvent {
        canaryMatch = canaryMatch == null ? List.of() : List.copyOf(canaryMatch);
    }
}

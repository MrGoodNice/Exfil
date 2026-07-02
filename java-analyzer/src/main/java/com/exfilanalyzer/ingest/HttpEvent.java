package com.exfilanalyzer.ingest;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record HttpEvent(
        String ts,
        @JsonProperty("run_id") String runId,
        @JsonProperty("sample_id") String sampleId,
        @JsonProperty("flow_id") String flowId,
        String method,
        String host,
        String path,
        boolean tls,
        @JsonProperty("opaque_reason") String opaqueReason,
        @JsonProperty("canary_match") List<String> canaryMatch,
        @JsonProperty("request_body_sha256") String requestBodySha256,
        @JsonProperty("response_body_sha256") String responseBodySha256,
        boolean upstream) {
    public HttpEvent {
        canaryMatch = canaryMatch == null ? List.of() : List.copyOf(canaryMatch);
    }
}

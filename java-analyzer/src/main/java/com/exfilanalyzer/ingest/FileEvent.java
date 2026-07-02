package com.exfilanalyzer.ingest;

import com.fasterxml.jackson.annotation.JsonProperty;

public record FileEvent(
        String ts,
        @JsonProperty("run_id") String runId,
        @JsonProperty("sample_id") String sampleId,
        int pid,
        Integer tgid,
        String comm,
        String path,
        @JsonProperty("is_canary") boolean isCanary,
        @JsonProperty("container_id") String containerId,
        @JsonProperty("cgroup_id") String cgroupId) {}

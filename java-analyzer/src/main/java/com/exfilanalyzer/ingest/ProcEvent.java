package com.exfilanalyzer.ingest;

import com.fasterxml.jackson.annotation.JsonProperty;

public record ProcEvent(
        String ts,
        @JsonProperty("run_id") String runId,
        @JsonProperty("sample_id") String sampleId,
        int pid,
        int ppid,
        int tgid,
        String comm,
        String exe,
        @JsonProperty("argv_hash") String argvHash,
        String event,
        @JsonProperty("container_id") String containerId,
        @JsonProperty("cgroup_id") String cgroupId) {}

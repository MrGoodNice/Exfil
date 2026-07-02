package com.exfilanalyzer.ingest;

import com.fasterxml.jackson.annotation.JsonProperty;

public record NetworkEvent(
        String ts,
        @JsonProperty("run_id") String runId,
        @JsonProperty("sample_id") String sampleId,
        String source,
        @JsonProperty("flow_id") String flowId,
        Integer pid,
        @JsonProperty("src_ip") String srcIp,
        @JsonProperty("src_port") Integer srcPort,
        @JsonProperty("dst_ip") String dstIp,
        @JsonProperty("dst_port") int dstPort,
        String proto,
        Integer retval,
        @JsonProperty("container_id") String containerId,
        @JsonProperty("cgroup_id") String cgroupId) {}

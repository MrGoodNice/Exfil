package com.exfilanalyzer.classify;

import com.exfilanalyzer.correlate.EgressEvent;
import java.util.List;

public record ClassifiedEgress(
        EgressEvent egress,
        Disposition disposition,
        DownloadState downloadState,
        List<String> reasons) {
    public ClassifiedEgress {
        reasons = List.copyOf(reasons);
    }
}

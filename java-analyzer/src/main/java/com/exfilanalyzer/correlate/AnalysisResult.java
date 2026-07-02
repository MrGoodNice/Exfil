package com.exfilanalyzer.correlate;

import com.exfilanalyzer.ingest.JsonlParseError;
import java.util.List;

public record AnalysisResult(List<CorrelatedRun> runs, List<JsonlParseError> parseErrors) {
    public AnalysisResult {
        runs = List.copyOf(runs);
        parseErrors = List.copyOf(parseErrors);
    }
}

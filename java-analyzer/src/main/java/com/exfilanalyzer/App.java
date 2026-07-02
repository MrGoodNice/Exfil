package com.exfilanalyzer;

import com.exfilanalyzer.correlate.AnalysisResult;
import com.exfilanalyzer.correlate.EventCorrelator;
import com.exfilanalyzer.ingest.JsonlReader;
import com.exfilanalyzer.ingest.RunEvents;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Path;

public final class App {
    private App() {
    }

    public static String name() {
        return "exfil-analyzer-java-analyzer";
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2 || !"analyze".equals(args[0])) {
            System.err.println("usage: java-analyzer analyze <run-dir>");
            System.exit(2);
        }
        RunEvents events = new JsonlReader().readRun(Path.of(args[1]));
        AnalysisResult result = new EventCorrelator().correlate(events);
        ObjectMapper mapper = new ObjectMapper();
        System.out.println(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(result));
    }
}

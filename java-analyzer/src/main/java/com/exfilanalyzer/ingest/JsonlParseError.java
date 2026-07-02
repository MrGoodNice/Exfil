package com.exfilanalyzer.ingest;

public record JsonlParseError(String fileName, int line, String message, String rawLine) {}

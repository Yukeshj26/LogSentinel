package com.forensics.loganalyzer.parsing;

import com.forensics.loganalyzer.model.LogEntry;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Map;

/** Immutable batch-read result, including rejected lines for auditability. */
public record LogReadResult(List<LogEntry> entries, List<ParseError> errors, Charset charset, Map<LogFormat, Long> formatCounts) {
    public LogReadResult {
        entries = List.copyOf(entries);
        errors = List.copyOf(errors);
        formatCounts = Map.copyOf(formatCounts);
    }
}

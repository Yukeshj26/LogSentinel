package com.forensics.loganalyzer.parsing;

import java.util.Objects;

/** Details retained for a line that could not be turned into a usable entry. */
public record ParseError(long lineNumber, String rawLine, String reason) {
    public ParseError {
        if (lineNumber < 1) throw new IllegalArgumentException("lineNumber must be positive");
        rawLine = Objects.requireNonNullElse(rawLine, "");
        reason = Objects.requireNonNullElse(reason, "Unknown parsing error");
    }
}

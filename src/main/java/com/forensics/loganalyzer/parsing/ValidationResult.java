package com.forensics.loganalyzer.parsing;

import com.forensics.loganalyzer.model.LogEntry;
import java.util.Optional;

/** Result of validating a candidate parsed entry. */
public record ValidationResult(Optional<LogEntry> entry, Optional<String> error) {
    public static ValidationResult valid(LogEntry entry) { return new ValidationResult(Optional.of(entry), Optional.empty()); }
    public static ValidationResult invalid(String reason) { return new ValidationResult(Optional.empty(), Optional.of(reason)); }
}

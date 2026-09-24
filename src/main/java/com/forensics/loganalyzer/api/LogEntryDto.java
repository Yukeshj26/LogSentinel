package com.forensics.loganalyzer.api;

import com.forensics.loganalyzer.model.LogEntry;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/** JSON-serializable DTO for a single log entry. */
public record LogEntryDto(
        String timestamp,
        String username,
        String ipAddress,
        String action,
        String statusCode,
        String rawLine) {

    public static LogEntryDto from(LogEntry entry) {
        return new LogEntryDto(
                DateTimeFormatter.ISO_INSTANT.format(entry.timestamp()),
                entry.username(),
                entry.ipAddress(),
                entry.action().name(),
                entry.statusCode().name(),
                entry.rawLine());
    }
}

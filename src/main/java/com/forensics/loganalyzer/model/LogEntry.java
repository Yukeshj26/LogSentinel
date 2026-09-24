package com.forensics.loganalyzer.model;

import java.time.Instant;
import java.util.Objects;

/** Immutable, validated representation of one raw log line. */
public record LogEntry(
        Instant timestamp,
        String username,
        String ipAddress,
        ActionType action,
        StatusCode statusCode,
        String rawLine) {

    public LogEntry {
        Objects.requireNonNull(timestamp, "timestamp must not be null");
        username = requireText(username, "username");
        ipAddress = requireText(ipAddress, "ipAddress");
        action = Objects.requireNonNull(action, "action must not be null");
        statusCode = Objects.requireNonNull(statusCode, "statusCode must not be null");
        rawLine = requireText(rawLine, "rawLine");
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(field + " must not be blank");
        return value.trim();
    }
}

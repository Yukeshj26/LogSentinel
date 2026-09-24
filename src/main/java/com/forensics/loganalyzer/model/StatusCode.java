package com.forensics.loganalyzer.model;

/** Normalized outcome of a log event. */
public enum StatusCode {
    SUCCESS, FAILURE, UNAUTHORIZED, NOT_FOUND, SERVER_ERROR, INFO, UNKNOWN;

    public static StatusCode from(String value) {
        if (value == null || value.isBlank()) return UNKNOWN;
        String normalized = value.trim().toUpperCase(java.util.Locale.ROOT);
        return switch (normalized) {
            case "200", "201", "202", "204", "OK", "SUCCESS", "ACCEPTED", "PASSED" -> SUCCESS;
            case "400", "FAIL", "FAILURE", "FAILED", "ERROR", "DENIED", "REJECTED" -> FAILURE;
            case "401", "403", "UNAUTHORIZED", "FORBIDDEN" -> UNAUTHORIZED;
            case "404", "NOT_FOUND" -> NOT_FOUND;
            case "500", "501", "502", "503", "SERVER_ERROR" -> SERVER_ERROR;
            case "INFO", "NOTICE" -> INFO;
            default -> UNKNOWN;
        };
    }
}

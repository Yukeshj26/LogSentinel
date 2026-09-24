package com.forensics.loganalyzer.model;

import java.util.Locale;

/** A normalized action extracted from a supported log source. */
public enum ActionType {
    LOGIN, LOGOUT, FILE_ACCESS, CREATE, DELETE, UPDATE, EXECUTE, NETWORK, UNKNOWN;

    public static ActionType from(String value) {
        if (value == null || value.isBlank()) return UNKNOWN;
        String normalized = value.trim().toUpperCase(Locale.ROOT).replace('-', '_').replace(' ', '_');
        return switch (normalized) {
            case "LOGIN", "LOG_IN", "AUTH", "AUTHENTICATION", "ACCEPTED", "SUCCESS" -> LOGIN;
            case "LOGOUT", "LOG_OUT" -> LOGOUT;
            case "READ", "GET", "ACCESS", "FILE_ACCESS" -> FILE_ACCESS;
            case "CREATE", "POST", "PUT" -> CREATE;
            case "DELETE", "REMOVE" -> DELETE;
            case "UPDATE", "PATCH", "WRITE" -> UPDATE;
            case "EXEC", "EXECUTE", "RUN" -> EXECUTE;
            case "CONNECT", "DISCONNECT", "NETWORK" -> NETWORK;
            default -> UNKNOWN;
        };
    }
}

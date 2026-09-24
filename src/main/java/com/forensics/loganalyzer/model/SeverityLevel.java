package com.forensics.loganalyzer.model;

/** Normalized severity level for a detected threat. */
public enum SeverityLevel {
    LOW, MEDIUM, HIGH, CRITICAL;

    public String label() {
        return name().charAt(0) + name().substring(1).toLowerCase();
    }
}

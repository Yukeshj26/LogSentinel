package com.forensics.loganalyzer.detection;

/** Categorizes the kind of threat detected. */
public enum ThreatType {
    BRUTE_FORCE,
    REPEATED_LOGIN_FAILURE,
    UNAUTHORIZED_ACCESS,
    ANOMALOUS_BEHAVIOR;

    public String label() {
        return name().replace('_', ' ');
    }
}

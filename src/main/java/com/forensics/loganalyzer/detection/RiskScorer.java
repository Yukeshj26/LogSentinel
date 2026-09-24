package com.forensics.loganalyzer.detection;

/** Scores a detected threat on a 0�100 scale based on type and event count. */
public final class RiskScorer {

    public double score(ThreatType type, int eventCount) {
        double base = switch (type) {
            case BRUTE_FORCE           -> 70.0;
            case REPEATED_LOGIN_FAILURE -> 45.0;
            case UNAUTHORIZED_ACCESS    -> 55.0;
            case ANOMALOUS_BEHAVIOR     -> 50.0;
        };
        // Scale up modestly with event count, capped at 100
        double scaled = base + Math.min(eventCount * 2.0, 30.0);
        return Math.min(scaled, 100.0);
    }
}

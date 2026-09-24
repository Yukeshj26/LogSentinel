package com.forensics.loganalyzer.detection;

import com.forensics.loganalyzer.model.SeverityLevel;
import java.time.Instant;
import java.util.Objects;

/** Immutable representation of a detected security threat. */
public record ThreatEvent(
        ThreatType type,
        String username,
        String ipAddress,
        String description,
        Instant detectedAt,
        double score,
        SeverityLevel severity,
        int contributingCount) {

    public ThreatEvent {
        Objects.requireNonNull(type, "type must not be null");
        Objects.requireNonNull(description, "description must not be null");
        Objects.requireNonNull(detectedAt, "detectedAt must not be null");
        Objects.requireNonNull(severity, "severity must not be null");
        username = username == null ? "" : username;
        ipAddress = ipAddress == null ? "" : ipAddress;
        if (score < 0 || score > 100) throw new IllegalArgumentException("score must be 0-100");
        if (contributingCount < 1) throw new IllegalArgumentException("contributingCount must be >= 1");
    }

    /** Unique key for deduplication in streaming mode. */
    public String deduplicationKey() {
        return type + "|" + username + "|" + ipAddress;
    }
}

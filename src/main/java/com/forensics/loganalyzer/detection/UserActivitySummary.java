package com.forensics.loganalyzer.detection;

import java.util.Set;

/** Tracks distinct IP addresses seen for a single user. */
public record UserActivitySummary(String username, Set<String> distinctIpAddresses) {

    public UserActivitySummary {
        if (username == null || username.isBlank()) throw new IllegalArgumentException("username must not be blank");
        distinctIpAddresses = Set.copyOf(distinctIpAddresses);
    }
}

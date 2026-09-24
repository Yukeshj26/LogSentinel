package com.forensics.loganalyzer.detection;

import com.forensics.loganalyzer.model.LogEntry;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Builds per-user activity summaries from a batch of log entries. */
public final class UserBehaviorTracker {

    /** Anomalous if a user logs in from this many or more distinct IPs. */
    public static final int ANOMALOUS_IP_THRESHOLD = 3;

    public Map<String, UserActivitySummary> summarize(List<LogEntry> entries) {
        Map<String, Set<String>> ipsByUser = new HashMap<>();
        for (LogEntry entry : entries) {
            ipsByUser.computeIfAbsent(entry.username(), k -> new HashSet<>())
                     .add(entry.ipAddress());
        }
        Map<String, UserActivitySummary> summaries = new HashMap<>();
        ipsByUser.forEach((user, ips) -> summaries.put(user, new UserActivitySummary(user, ips)));
        return summaries;
    }

    public boolean isAnomalous(UserActivitySummary summary) {
        return summary.distinctIpAddresses().size() >= ANOMALOUS_IP_THRESHOLD;
    }
}

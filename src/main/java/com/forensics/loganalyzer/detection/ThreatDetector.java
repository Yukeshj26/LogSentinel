package com.forensics.loganalyzer.detection;

import com.forensics.loganalyzer.model.ActionType;
import com.forensics.loganalyzer.model.LogEntry;
import com.forensics.loganalyzer.model.StatusCode;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Rule-based threat detector for batches of validated LogEntry objects.
 * Detection rules:
 *   BRUTE_FORCE            -- >= 5 login failures from one IP within 60 seconds
 *   REPEATED_LOGIN_FAILURE -- >= 3 login failures from one IP within 10 minutes (sub-brute-force)
 *   UNAUTHORIZED_ACCESS    -- any UNAUTHORIZED status code event
 *   ANOMALOUS_BEHAVIOR     -- one user authenticating from >= 3 distinct IPs
 */
public final class ThreatDetector {

    public static final int BRUTE_FORCE_THRESHOLD = 5;
    public static final long BRUTE_FORCE_WINDOW_SECONDS = 60;

    public static final int REPEATED_FAILURE_THRESHOLD = 3;
    public static final long REPEATED_FAILURE_WINDOW_SECONDS = 600;

    private final RiskScorer riskScorer;
    private final SeverityClassifier severityClassifier;
    private final UserBehaviorTracker behaviorTracker;

    public ThreatDetector() {
        this(new RiskScorer(), new SeverityClassifier(), new UserBehaviorTracker());
    }

    public ThreatDetector(RiskScorer riskScorer, SeverityClassifier severityClassifier, UserBehaviorTracker behaviorTracker) {
        this.riskScorer = riskScorer;
        this.severityClassifier = severityClassifier;
        this.behaviorTracker = behaviorTracker;
    }

    public List<ThreatEvent> detect(List<LogEntry> entries) {
        List<ThreatEvent> threats = new ArrayList<>();
        threats.addAll(detectFailureBurstsByIp(entries));
        threats.addAll(detectUnauthorizedAccess(entries));
        threats.addAll(detectAnomalousUserBehavior(entries));
        return threats;
    }

    private List<ThreatEvent> detectFailureBurstsByIp(List<LogEntry> entries) {
        List<ThreatEvent> threats = new ArrayList<>();
        Map<String, List<LogEntry>> failuresByIp = new LinkedHashMap<>();
        for (LogEntry entry : entries) {
            if (entry.action() == ActionType.LOGIN && entry.statusCode() == StatusCode.FAILURE) {
                failuresByIp.computeIfAbsent(entry.ipAddress(), k -> new ArrayList<>()).add(entry);
            }
        }
        for (Map.Entry<String, List<LogEntry>> ipEntry : failuresByIp.entrySet()) {
            String ip = ipEntry.getKey();
            List<LogEntry> failures = new ArrayList<>(ipEntry.getValue());
            failures.sort((a, b) -> a.timestamp().compareTo(b.timestamp()));

            List<LogEntry> bruteForceWindow = firstWindowReachingThreshold(failures, BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW_SECONDS);
            if (bruteForceWindow != null) {
                threats.add(buildThreatEvent(ThreatType.BRUTE_FORCE, "", ip,
                        bruteForceWindow.size() + " failed login attempts from " + ip + " within " + BRUTE_FORCE_WINDOW_SECONDS + " seconds",
                        bruteForceWindow));
                continue;
            }

            List<LogEntry> repeatedWindow = firstWindowReachingThreshold(failures, REPEATED_FAILURE_THRESHOLD, REPEATED_FAILURE_WINDOW_SECONDS);
            if (repeatedWindow != null) {
                threats.add(buildThreatEvent(ThreatType.REPEATED_LOGIN_FAILURE, "", ip,
                        repeatedWindow.size() + " failed login attempts from " + ip + " within " + (REPEATED_FAILURE_WINDOW_SECONDS / 60) + " minutes",
                        repeatedWindow));
            }
        }
        return threats;
    }

    private List<LogEntry> firstWindowReachingThreshold(List<LogEntry> sorted, int threshold, long windowSeconds) {
        int left = 0;
        int burstStart = -1;
        for (int right = 0; right < sorted.size(); right++) {
            Instant rightTime = sorted.get(right).timestamp();
            while (sorted.get(left).timestamp().plusSeconds(windowSeconds).isBefore(rightTime)) {
                left++;
            }
            int windowSize = right - left + 1;
            if (windowSize >= threshold) {
                burstStart = (burstStart == -1) ? left : Math.min(burstStart, left);
            } else if (burstStart != -1) {
                return new ArrayList<>(sorted.subList(burstStart, right));
            }
        }
        return (burstStart == -1) ? null : new ArrayList<>(sorted.subList(burstStart, sorted.size()));
    }

    private List<ThreatEvent> detectUnauthorizedAccess(List<LogEntry> entries) {
        List<ThreatEvent> threats = new ArrayList<>();
        for (LogEntry entry : entries) {
            if (entry.statusCode() == StatusCode.UNAUTHORIZED) {
                threats.add(buildThreatEvent(ThreatType.UNAUTHORIZED_ACCESS, entry.username(), entry.ipAddress(),
                        "Unauthorized access attempt by '" + entry.username() + "' from " + entry.ipAddress(),
                        List.of(entry)));
            }
        }
        return threats;
    }

    private List<ThreatEvent> detectAnomalousUserBehavior(List<LogEntry> entries) {
        List<ThreatEvent> threats = new ArrayList<>();
        Map<String, UserActivitySummary> summaries = behaviorTracker.summarize(entries);
        for (UserActivitySummary summary : summaries.values()) {
            if (!behaviorTracker.isAnomalous(summary)) continue;
            List<LogEntry> contributing = entries.stream()
                    .filter(e -> e.username().equals(summary.username()))
                    .toList();
            threats.add(buildThreatEvent(ThreatType.ANOMALOUS_BEHAVIOR, summary.username(), "",
                    "User '" + summary.username() + "' authenticated from " + summary.distinctIpAddresses().size() + " distinct IP addresses",
                    contributing));
        }
        return threats;
    }

    private ThreatEvent buildThreatEvent(ThreatType type, String username, String ipAddress,
                                          String description, List<LogEntry> contributing) {
        double score = riskScorer.score(type, contributing.size());
        Instant detectedAt = contributing.stream().map(LogEntry::timestamp).max(Instant::compareTo).orElseThrow();
        return new ThreatEvent(type, username, ipAddress, description, detectedAt, score,
                severityClassifier.classify(score), contributing.size());
    }
}

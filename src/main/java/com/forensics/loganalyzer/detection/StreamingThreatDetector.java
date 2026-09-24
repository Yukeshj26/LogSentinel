package com.forensics.loganalyzer.detection;

import com.forensics.loganalyzer.model.LogEntry;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Stateful wrapper around ThreatDetector for real-time streaming use.
 * Maintains a rolling buffer of recent entries across poll cycles so that
 * threats spanning multiple polling windows (e.g. brute-force delivered
 * one line at a time) are correctly detected. Deduplicates already-reported
 * threats so an ongoing incident does not re-alert on every new entry.
 */
public final class StreamingThreatDetector {

    private final ThreatDetector detector;
    private final long bufferWindowSeconds;

    private final List<LogEntry> buffer = new ArrayList<>();
    private final Set<String> alreadyAlerted = new LinkedHashSet<>();

    public StreamingThreatDetector() {
        this(new ThreatDetector(),
             Math.max(ThreatDetector.BRUTE_FORCE_WINDOW_SECONDS, ThreatDetector.REPEATED_FAILURE_WINDOW_SECONDS));
    }

    public StreamingThreatDetector(ThreatDetector detector, long bufferWindowSeconds) {
        this.detector = detector;
        this.bufferWindowSeconds = bufferWindowSeconds;
    }

    public synchronized List<ThreatEvent> processNewEntries(List<LogEntry> newEntries) {
        buffer.addAll(newEntries);
        pruneOldEntries();

        List<ThreatEvent> freshThreats = new ArrayList<>();
        for (ThreatEvent threat : detector.detect(buffer)) {
            if (alreadyAlerted.add(threat.deduplicationKey())) {
                freshThreats.add(threat);
            }
        }
        return freshThreats;
    }

    public synchronized int bufferSize() { return buffer.size(); }

    public synchronized void reset() {
        buffer.clear();
        alreadyAlerted.clear();
    }

    private void pruneOldEntries() {
        if (buffer.isEmpty()) return;
        Instant latest = buffer.stream().map(LogEntry::timestamp).max(Instant::compareTo).orElseThrow();
        Instant cutoff = latest.minusSeconds(bufferWindowSeconds);
        buffer.removeIf(e -> e.timestamp().isBefore(cutoff));
    }
}

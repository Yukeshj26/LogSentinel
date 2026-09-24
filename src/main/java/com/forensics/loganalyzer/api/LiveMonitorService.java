package com.forensics.loganalyzer.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.forensics.loganalyzer.detection.StreamingThreatDetector;
import com.forensics.loganalyzer.detection.ThreatEvent;
import com.forensics.loganalyzer.model.ActionType;
import com.forensics.loganalyzer.model.LogEntry;
import com.forensics.loganalyzer.model.StatusCode;
import com.forensics.loganalyzer.parsing.LogReadResult;
import com.forensics.loganalyzer.parsing.WindowsSecurityLogReader;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Background service that continuously polls the Windows Security Event Log
 * for new logon events and pushes them to connected SSE clients.
 * Falls back to simulated demo data when running without admin rights or on non-Windows OS.
 */
@Service
public class LiveMonitorService {

    private final WindowsSecurityLogReader windowsReader = new WindowsSecurityLogReader();
    private final StreamingThreatDetector streamingDetector = new StreamingThreatDetector();
    private final ObjectMapper mapper = new ObjectMapper();

    private final List<SseEmitter> emitters = new CopyOnWriteArrayList<>();
    private final AtomicBoolean demoMode = new AtomicBoolean(false);
    private final AtomicLong totalEvents = new AtomicLong(0);
    private final AtomicLong totalThreats = new AtomicLong(0);
    private final AtomicLong totalFailures = new AtomicLong(0);
    private Instant lastSeenTimestamp = Instant.EPOCH;

    private static final String[] DEMO_USERS = {"jsmith", "admin", "bwayne", "alice", "root", "guest", "sysadmin"};
    private static final String[] DEMO_IPS = {"192.168.1.10", "10.0.0.5", "203.0.113.9", "172.16.0.9", "45.33.10.20", "91.198.22.5", "198.51.100.7"};
    private final Random random = new Random();

    public SseEmitter createEmitter() {
        SseEmitter emitter = new SseEmitter(Long.MAX_VALUE);
        emitters.add(emitter);
        emitter.onCompletion(() -> emitters.remove(emitter));
        emitter.onTimeout(() -> emitters.remove(emitter));
        emitter.onError(e -> emitters.remove(emitter));

        // Send initial status
        try {
            emitter.send(SseEmitter.event()
                .name("status")
                .data(buildStatusJson()));
        } catch (IOException ignored) {
            emitters.remove(emitter);
        }
        return emitter;
    }

    @Scheduled(fixedDelay = 5000)
    public void pollAndBroadcast() {
        List<LogEntry> newEntries = new ArrayList<>();
        boolean isDemo = false;

        try {
            if (!System.getProperty("os.name", "").toLowerCase().contains("win")) {
                throw new IOException("Not Windows");
            }
            LogReadResult result = windowsReader.readLatest(100);
            for (LogEntry entry : result.entries()) {
                if (entry.timestamp().isAfter(lastSeenTimestamp)) {
                    newEntries.add(entry);
                    if (newEntries.size() > 0) {
                        lastSeenTimestamp = newEntries.stream()
                            .map(LogEntry::timestamp)
                            .max(Instant::compareTo)
                            .orElse(lastSeenTimestamp);
                    }
                }
            }
            demoMode.set(false);
        } catch (IOException | IllegalArgumentException e) {
            // Fallback: generate realistic demo entries
            isDemo = true;
            demoMode.set(true);
            newEntries.addAll(generateDemoEntries());
        }

        if (newEntries.isEmpty() && !isDemo) return;

        List<ThreatEvent> newThreats = streamingDetector.processNewEntries(newEntries);

        long failures = newEntries.stream().filter(e -> e.statusCode() == StatusCode.FAILURE || e.statusCode() == StatusCode.UNAUTHORIZED).count();
        totalEvents.addAndGet(newEntries.size());
        totalFailures.addAndGet(failures);
        totalThreats.addAndGet(newThreats.size());

        broadcast(newEntries, newThreats);
    }

    @Scheduled(fixedDelay = 15000)
    public void sendHeartbeat() {
        Map<String, Object> hb = new LinkedHashMap<>();
        hb.put("demo", demoMode.get());
        hb.put("emitters", emitters.size());
        broadcastRaw("heartbeat", hb);
        broadcastRaw("stats", buildStatsMap());
    }

    private void broadcast(List<LogEntry> entries, List<ThreatEvent> threats) {
        for (LogEntry entry : entries) {
            broadcastRaw("log-entry", LogEntryDto.from(entry));
        }
        for (ThreatEvent threat : threats) {
            broadcastRaw("threat", ThreatEventDto.from(threat));
        }
        broadcastRaw("stats", buildStatsMap());
    }

    private void broadcastRaw(String eventName, Object payload) {
        String json;
        try { json = mapper.writeValueAsString(payload); } catch (Exception e) { return; }
        List<SseEmitter> dead = new ArrayList<>();
        for (SseEmitter emitter : emitters) {
            try {
                emitter.send(SseEmitter.event().name(eventName).data(json));
            } catch (IOException ex) {
                dead.add(emitter);
            }
        }
        emitters.removeAll(dead);
    }

    private String buildStatusJson() {
        try {
            return mapper.writeValueAsString(buildStatsMap());
        } catch (Exception e) { return "{}"; }
    }

    private Map<String, Object> buildStatsMap() {
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("totalEvents", totalEvents.get());
        stats.put("totalThreats", totalThreats.get());
        stats.put("totalFailures", totalFailures.get());
        stats.put("demoMode", demoMode.get());
        stats.put("bufferSize", streamingDetector.bufferSize());
        stats.put("isAdmin", AdminController.isRunningAsAdmin());
        stats.put("isWindows", AdminController.isWindows());
        stats.put("canElevate", AdminController.isWindows() && !AdminController.isRunningAsAdmin());
        return stats;
    }

    public Map<String, Object> getStatus() { return buildStatsMap(); }
    public boolean isDemoMode() { return demoMode.get(); }

    private List<LogEntry> generateDemoEntries() {
        List<LogEntry> entries = new ArrayList<>();
        int count = 1 + random.nextInt(3);
        for (int i = 0; i < count; i++) {
            String user = DEMO_USERS[random.nextInt(DEMO_USERS.length)];
            String ip = DEMO_IPS[random.nextInt(DEMO_IPS.length)];
            boolean success = random.nextInt(10) > 3;
            ActionType action = random.nextInt(10) > 6 ? ActionType.LOGOUT :
                                random.nextInt(10) > 7 ? ActionType.FILE_ACCESS : ActionType.LOGIN;
            StatusCode status = success ? StatusCode.SUCCESS :
                                (random.nextBoolean() ? StatusCode.FAILURE : StatusCode.UNAUTHORIZED);
            String raw = Instant.now() + " user=" + user + " ip=" + ip + " action=" + action + " status=" + status;
            try {
                entries.add(new LogEntry(Instant.now().minusMillis(random.nextInt(4000)), user, ip, action, status, raw));
            } catch (Exception ignored) {}
        }

        // Occasionally simulate a brute-force burst from a single IP
        if (random.nextInt(20) == 0) {
            String attackerIp = "203.0.113." + (1 + random.nextInt(50));
            Instant base = Instant.now().minusSeconds(55);
            for (int i = 0; i < 6; i++) {
                String user = DEMO_USERS[random.nextInt(DEMO_USERS.length)];
                String raw = base.plusSeconds(i * 9) + " user=" + user + " ip=" + attackerIp + " action=LOGIN status=FAILURE";
                try {
                    entries.add(new LogEntry(base.plusSeconds(i * 9), user, attackerIp, ActionType.LOGIN, StatusCode.FAILURE, raw));
                } catch (Exception ignored) {}
            }
        }
        return entries;
    }
}

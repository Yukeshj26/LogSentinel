package com.forensics.loganalyzer.storage;

import com.forensics.loganalyzer.detection.ThreatEvent;
import com.forensics.loganalyzer.model.LogEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class StorageService {

    private static final Logger log = LoggerFactory.getLogger(StorageService.class);

    private final LogEntryRepository logRepository;
    private final ThreatRepository threatRepository;

    public StorageService(LogEntryRepository logRepository, ThreatRepository threatRepository) {
        this.logRepository = logRepository;
        this.threatRepository = threatRepository;
    }

    @Transactional
    public void saveLogEntries(List<LogEntry> entries, String source) {
        if (entries == null || entries.isEmpty()) return;
        List<PersistedLogEntry> entities = entries.stream()
                .map(e -> new PersistedLogEntry(e, source))
                .toList();
        logRepository.saveAll(entities);
    }

    @Transactional
    public void saveThreats(List<ThreatEvent> threats, String source) {
        if (threats == null || threats.isEmpty()) return;
        List<PersistedThreat> entities = threats.stream()
                .map(t -> new PersistedThreat(t, source))
                .toList();
        threatRepository.saveAll(entities);
    }

    public List<PersistedLogEntry> getRecentLogs(int limit) {
        return logRepository.findTop100ByOrderByTimestampDesc();
    }

    public List<PersistedThreat> getRecentThreats(int limit) {
        return threatRepository.findTop100ByOrderByDetectedAtDesc();
    }

    public long getTotalLogsCount() {
        return logRepository.count();
    }

    public long getTotalThreatsCount() {
        return threatRepository.count();
    }

    public long getTotalFailuresCount() {
        return logRepository.countByStatusCodeIn(List.of("FAILURE", "UNAUTHORIZED"));
    }

    public List<PersistedLogEntry> getAllLogsForExport() {
        return logRepository.findTop500ByOrderByTimestampDesc();
    }

    public java.util.Map<String, Object> getEntityDossier(String type, String value) {
        java.util.Map<String, Object> dossier = new java.util.LinkedHashMap<>();
        dossier.put("type", type);
        dossier.put("value", value);

        List<PersistedLogEntry> logs;
        List<PersistedThreat> threats;
        long totalCount;

        if ("user".equalsIgnoreCase(type)) {
            logs = logRepository.findTop50ByUsernameOrderByTimestampDesc(value);
            threats = threatRepository.findByUsernameOrderByDetectedAtDesc(value);
            totalCount = logRepository.countByUsername(value);
        } else {
            logs = logRepository.findTop50ByIpAddressOrderByTimestampDesc(value);
            threats = threatRepository.findByIpAddressOrderByDetectedAtDesc(value);
            totalCount = logRepository.countByIpAddress(value);
        }

        long successCount = logs.stream().filter(l -> "SUCCESS".equalsIgnoreCase(l.getStatusCode())).count();
        long failureCount = logs.stream().filter(l -> "FAILURE".equalsIgnoreCase(l.getStatusCode()) || "UNAUTHORIZED".equalsIgnoreCase(l.getStatusCode())).count();

        dossier.put("totalEvents", totalCount);
        dossier.put("successCount", successCount);
        dossier.put("failureCount", failureCount);
        dossier.put("threatCount", threats.size());
        dossier.put("threats", threats);
        dossier.put("recentLogs", logs);

        if (!logs.isEmpty()) {
            dossier.put("lastSeen", logs.get(0).getTimestamp());
            dossier.put("firstSeen", logs.get(logs.size() - 1).getTimestamp());
        }

        return dossier;
    }

    @Transactional
    public void clearAll() {
        logRepository.deleteAllInBatch();
        threatRepository.deleteAllInBatch();
        log.info("Cleared all persisted logs and threats from H2 database");
    }
}

package com.forensics.loganalyzer.api;

import com.forensics.loganalyzer.detection.ThreatEvent;
import com.forensics.loganalyzer.model.LogEntry;
import com.forensics.loganalyzer.parsing.LogReadResult;
import com.forensics.loganalyzer.parsing.LogReader;
import com.forensics.loganalyzer.detection.ThreatDetector;
import com.forensics.loganalyzer.parsing.ParseError;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;

/** REST API and SSE endpoint for LogSentinel. */
@RestController
@RequestMapping("/api")
public class AnalysisController {

    private final LiveMonitorService liveMonitorService;
    private final com.forensics.loganalyzer.storage.StorageService storageService;
    private final ThreatDetector threatDetector = new ThreatDetector();
    private final LogReader logReader = new LogReader();

    public AnalysisController(LiveMonitorService liveMonitorService, com.forensics.loganalyzer.storage.StorageService storageService) {
        this.liveMonitorService = liveMonitorService;
        this.storageService = storageService;
    }

    /** SSE stream � clients subscribe here for real-time log and threat events. */
    @GetMapping(value = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter stream() {
        return liveMonitorService.createEmitter();
    }

    /** Current session statistics. */
    @GetMapping("/status")
    public Map<String, Object> status() {
        return liveMonitorService.getStatus();
    }

    /** Historical logs and threats for initial load / page refresh. */
    @GetMapping("/history")
    public Map<String, Object> history() {
        return liveMonitorService.getInitialState();
    }

    /** Clear all persisted logs and threats from database and session buffer. */
    @DeleteMapping("/history")
    public Map<String, Object> clearHistory() {
        liveMonitorService.clearAll();
        return Map.of("status", "cleared");
    }

    /** Retrieve deep forensic dossier for an IP or username. */
    @GetMapping("/dossier")
    public Map<String, Object> getDossier(
            @RequestParam(name = "type", defaultValue = "ip") String type,
            @RequestParam(name = "value") String value) {
        return storageService.getEntityDossier(type, value);
    }

    /** Export audit logs in standard RFC 4180 CSV format. */
    @GetMapping(value = "/export/csv", produces = "text/csv")
    public org.springframework.http.ResponseEntity<String> exportCsv() {
        StringBuilder csv = new StringBuilder();
        csv.append("Timestamp,Username,IP_Address,Action,StatusCode,Source,RawLine\n");
        for (com.forensics.loganalyzer.storage.PersistedLogEntry e : storageService.getAllLogsForExport()) {
            csv.append(String.format("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
                    e.getTimestamp(),
                    e.getUsername() == null ? "" : e.getUsername().replace("\"", "\"\""),
                    e.getIpAddress() == null ? "" : e.getIpAddress().replace("\"", "\"\""),
                    e.getAction(),
                    e.getStatusCode(),
                    e.getSource() == null ? "" : e.getSource(),
                    e.getRawLine() == null ? "" : e.getRawLine().replace("\"", "\"\"")
            ));
        }
        return org.springframework.http.ResponseEntity.ok()
                .header(org.springframework.http.HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"logsentinel-audit.csv\"")
                .body(csv.toString());
    }

    /** One-shot historical analysis via multipart file upload. */
    @PostMapping("/analyze")
    public AnalysisResponse analyzeFile(@RequestParam("file") MultipartFile file) throws IOException {
        Path temp = Files.createTempFile("logsentinel-", ".log");
        try {
            file.transferTo(temp);
            return analyze(temp);
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    /** One-shot historical analysis via raw text in request body. */
    @PostMapping(value = "/analyze/text", consumes = MediaType.TEXT_PLAIN_VALUE)
    public AnalysisResponse analyzeText(@RequestBody String text) throws IOException {
        Path temp = Files.createTempFile("logsentinel-", ".log");
        try {
            Files.writeString(temp, text, StandardCharsets.UTF_8);
            return analyze(temp);
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    private AnalysisResponse analyze(Path path) throws IOException {
        LogReadResult result = logReader.readWithReport(path);
        List<ThreatEvent> threats = threatDetector.detect(result.entries());

        storageService.saveLogEntries(result.entries(), "FILE_ANALYSIS");
        storageService.saveThreats(threats, "FILE_ANALYSIS");

        List<LogEntryDto> entries = result.entries().stream().map(LogEntryDto::from).collect(Collectors.toList());
        List<ThreatEventDto> threatDtos = threats.stream().map(ThreatEventDto::from).collect(Collectors.toList());

        List<Map<String, Object>> errors = new ArrayList<>();
        for (ParseError e : result.errors()) {
            Map<String, Object> err = new LinkedHashMap<>();
            err.put("lineNumber", e.lineNumber());
            err.put("reason", e.reason());
            err.put("rawLine", e.rawLine());
            errors.add(err);
        }

        Map<String, Long> formats = new LinkedHashMap<>();
        result.formatCounts().forEach((k, v) -> formats.put(k.name(), v));

        return new AnalysisResponse(entries, threatDtos, errors, formats,
                result.charset().displayName(), entries.size(), errors.size(), threats.size());
    }

    public record AnalysisResponse(
            List<LogEntryDto> entries,
            List<ThreatEventDto> threats,
            List<Map<String, Object>> rejectedLines,
            Map<String, Long> formatCounts,
            String charset,
            int totalEntries,
            int totalRejected,
            int totalThreats) {}
}

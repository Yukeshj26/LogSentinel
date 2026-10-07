package com.forensics.loganalyzer.storage;

import com.forensics.loganalyzer.model.ActionType;
import com.forensics.loganalyzer.model.LogEntry;
import com.forensics.loganalyzer.model.StatusCode;
import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "persisted_log_entries", indexes = {
    @Index(name = "idx_log_timestamp", columnList = "timestamp"),
    @Index(name = "idx_log_user", columnList = "username"),
    @Index(name = "idx_log_ip", columnList = "ipAddress"),
    @Index(name = "idx_log_status", columnList = "statusCode")
})
public class PersistedLogEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Instant timestamp;

    @Column(length = 100)
    private String username;

    @Column(length = 50)
    private String ipAddress;

    @Column(nullable = false, length = 30)
    private String action;

    @Column(nullable = false, length = 30)
    private String statusCode;

    @Column(length = 2000)
    private String rawLine;

    @Column(length = 50)
    private String source;

    @Column(nullable = false)
    private Instant recordedAt;

    public PersistedLogEntry() {
    }

    public PersistedLogEntry(LogEntry entry, String source) {
        this.timestamp = entry.timestamp();
        this.username = entry.username();
        this.ipAddress = entry.ipAddress();
        this.action = entry.action().name();
        this.statusCode = entry.statusCode().name();
        this.rawLine = entry.rawLine();
        this.source = source != null ? source : "LIVE_STREAM";
        this.recordedAt = Instant.now();
    }

    public LogEntry toLogEntry() {
        ActionType at;
        try { at = ActionType.valueOf(this.action); } catch (Exception e) { at = ActionType.LOGIN; }
        StatusCode sc;
        try { sc = StatusCode.valueOf(this.statusCode); } catch (Exception e) { sc = StatusCode.UNKNOWN; }
        return new LogEntry(this.timestamp, this.username, this.ipAddress, at, sc, this.rawLine);
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Instant getTimestamp() { return timestamp; }
    public void setTimestamp(Instant timestamp) { this.timestamp = timestamp; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }

    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }

    public String getStatusCode() { return statusCode; }
    public void setStatusCode(String statusCode) { this.statusCode = statusCode; }

    public String getRawLine() { return rawLine; }
    public void setRawLine(String rawLine) { this.rawLine = rawLine; }

    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }

    public Instant getRecordedAt() { return recordedAt; }
    public void setRecordedAt(Instant recordedAt) { this.recordedAt = recordedAt; }
}

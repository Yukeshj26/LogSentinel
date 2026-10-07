package com.forensics.loganalyzer.storage;

import com.forensics.loganalyzer.detection.ThreatEvent;
import com.forensics.loganalyzer.detection.ThreatType;
import com.forensics.loganalyzer.model.SeverityLevel;
import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "persisted_threats", indexes = {
    @Index(name = "idx_threat_detected_at", columnList = "detectedAt"),
    @Index(name = "idx_threat_severity", columnList = "severity"),
    @Index(name = "idx_threat_type", columnList = "threatType"),
    @Index(name = "idx_threat_ip", columnList = "ipAddress")
})
public class PersistedThreat {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 50)
    private String threatType;

    @Column(nullable = false, length = 20)
    private String severity;

    @Column(length = 100)
    private String username;

    @Column(length = 50)
    private String ipAddress;

    @Column(length = 2000, nullable = false)
    private String description;

    @Column(nullable = false)
    private Instant detectedAt;

    @Column(nullable = false)
    private double score;

    @Column(nullable = false)
    private int contributingCount;

    @Column(nullable = false, length = 50)
    private String source;

    @Column(nullable = false)
    private Instant recordedAt;

    public PersistedThreat() {
    }

    public PersistedThreat(ThreatEvent event, String source) {
        this.threatType = event.type().name();
        this.severity = event.severity().name();
        this.username = event.username() != null ? event.username() : "";
        this.ipAddress = event.ipAddress() != null ? event.ipAddress() : "";
        this.description = event.description();
        this.detectedAt = event.detectedAt();
        this.score = Math.round(event.score() * 10.0) / 10.0;
        this.contributingCount = event.contributingCount();
        this.source = source != null ? source : "LIVE_STREAM";
        this.recordedAt = Instant.now();
    }

    public ThreatEvent toThreatEvent() {
        ThreatType tt;
        try { tt = ThreatType.valueOf(this.threatType); } catch (Exception e) { tt = ThreatType.UNAUTHORIZED_ACCESS; }
        SeverityLevel sl;
        try { sl = SeverityLevel.valueOf(this.severity); } catch (Exception e) { sl = SeverityLevel.MEDIUM; }
        return new ThreatEvent(tt, this.username, this.ipAddress, this.description, this.detectedAt, this.score, sl, this.contributingCount);
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getThreatType() { return threatType; }
    public void setThreatType(String threatType) { this.threatType = threatType; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public Instant getDetectedAt() { return detectedAt; }
    public void setDetectedAt(Instant detectedAt) { this.detectedAt = detectedAt; }

    public double getScore() { return score; }
    public void setScore(double score) { this.score = score; }

    public int getContributingCount() { return contributingCount; }
    public void setContributingCount(int contributingCount) { this.contributingCount = contributingCount; }

    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }

    public Instant getRecordedAt() { return recordedAt; }
    public void setRecordedAt(Instant recordedAt) { this.recordedAt = recordedAt; }
}

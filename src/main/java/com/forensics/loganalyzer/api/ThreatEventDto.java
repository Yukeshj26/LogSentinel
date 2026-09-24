package com.forensics.loganalyzer.api;

import com.forensics.loganalyzer.detection.ThreatEvent;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/** JSON-serializable DTO for a detected threat event. */
public record ThreatEventDto(
        String type,
        String severity,
        String username,
        String ipAddress,
        String description,
        String detectedAt,
        double score,
        int contributingCount) {

    public static ThreatEventDto from(ThreatEvent event) {
        return new ThreatEventDto(
                event.type().name(),
                event.severity().name(),
                event.username(),
                event.ipAddress(),
                event.description(),
                DateTimeFormatter.ISO_INSTANT.format(event.detectedAt()),
                Math.round(event.score() * 10.0) / 10.0,
                event.contributingCount());
    }
}

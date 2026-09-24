package com.forensics.loganalyzer.detection;

import com.forensics.loganalyzer.model.SeverityLevel;

/** Maps a numeric risk score (0�100) to a {@link SeverityLevel}. */
public final class SeverityClassifier {

    public SeverityLevel classify(double score) {
        if (score >= 85) return SeverityLevel.CRITICAL;
        if (score >= 65) return SeverityLevel.HIGH;
        if (score >= 40) return SeverityLevel.MEDIUM;
        return SeverityLevel.LOW;
    }
}

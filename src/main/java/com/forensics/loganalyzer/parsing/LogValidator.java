package com.forensics.loganalyzer.parsing;

import com.forensics.loganalyzer.model.LogEntry;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Pattern;

/** Ensures parsed records contain complete, trustworthy core fields. */
public final class LogValidator {
    private static final Pattern USERNAME = Pattern.compile("[A-Za-z0-9_.@-]{1,128}");

    public ValidationResult validate(LogEntry entry) {
        if (!USERNAME.matcher(entry.username()).matches()) return ValidationResult.invalid("Invalid username");
        if (!isLiteralIpAddress(entry.ipAddress())) return ValidationResult.invalid("Invalid IP address");
        if (entry.action().name().equals("UNKNOWN")) return ValidationResult.invalid("Unknown action");
        if (entry.statusCode().name().equals("UNKNOWN")) return ValidationResult.invalid("Unknown status code");
        return ValidationResult.valid(entry);
    }

    private boolean isLiteralIpAddress(String value) {
        // InetAddress accepts hostnames, so reject non-address characters before parsing.
        if (!value.matches("[0-9A-Fa-f:.]+")) return false;
        try { return InetAddress.getByName(value).getHostAddress() != null; }
        catch (UnknownHostException ignored) { return false; }
    }
}

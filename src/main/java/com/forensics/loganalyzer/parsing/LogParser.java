package com.forensics.loganalyzer.parsing;

import com.forensics.loganalyzer.model.ActionType;
import com.forensics.loganalyzer.model.LogEntry;
import com.forensics.loganalyzer.model.StatusCode;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.Month;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Parses application key/value, Linux auth syslog, and Common Log Format lines. */
public final class LogParser {
    private static final Pattern APPLICATION = Pattern.compile(
            "^(?<timestamp>\\S+)\\s+\\S+\\s+user=(?<user>\\S+)\\s+ip=(?<ip>\\S+)\\s+action=(?<action>\\S+)\\s+status=(?<status>\\S+).*$",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern SYSLOG = Pattern.compile(
            "^(?<month>[A-Z][a-z]{2})\\s+(?<day>\\d{1,2})\\s+(?<time>\\d{2}:\\d{2}:\\d{2})\\s+\\S+\\s+sshd(?:\\[\\d+])?:\\s+(?<outcome>Failed|Accepted)\\s+\\S+\\s+for\\s+(?:invalid user\\s+)?(?<user>\\S+)\\s+from\\s+(?<ip>[0-9A-Fa-f:.]+).*$",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern COMMON = Pattern.compile(
            "^(?<ip>\\S+)\\s+\\S+\\s+(?<user>\\S+)\\s+\\[(?<timestamp>[^]]+)]\\s+\\\"(?<method>[A-Z]+)\\s+[^ ]+\\s+[^\\\"]+\\\"\\s+(?<status>\\d{3}).*$",
            Pattern.CASE_INSENSITIVE);
    private static final DateTimeFormatter SYSLOG_TIME = DateTimeFormatter.ofPattern("MMM d HH:mm:ss", Locale.US);
    private static final DateTimeFormatter COMMON_TIME = DateTimeFormatter.ofPattern("d/MMM/uuuu:HH:mm:ss xx", Locale.US);
    private final Clock clock;

    public LogParser() { this(Clock.systemUTC()); }
    public LogParser(Clock clock) { this.clock = clock; }

    /** Returns an entry only when both parsing and validation succeed. */
    public Optional<LogEntry> parse(String line) {
        if (line == null || line.isBlank()) return Optional.empty();
        try {
            Matcher match = APPLICATION.matcher(line);
            if (match.matches()) return Optional.of(entry(Instant.parse(match.group("timestamp")), match.group("user"), match.group("ip"), ActionType.from(match.group("action")), StatusCode.from(match.group("status")), line));
            match = SYSLOG.matcher(line);
            if (match.matches()) {
                Month month = Month.from(SYSLOG_TIME.parse(match.group("month") + " " + match.group("day") + " " + match.group("time")));
                LocalDateTime time = LocalDateTime.of(Instant.now(clock).atOffset(ZoneOffset.UTC).getYear(), month, Integer.parseInt(match.group("day")), Integer.parseInt(match.group("time").substring(0, 2)), Integer.parseInt(match.group("time").substring(3, 5)), Integer.parseInt(match.group("time").substring(6, 8)));
                boolean accepted = match.group("outcome").equalsIgnoreCase("Accepted");
                return Optional.of(entry(time.toInstant(ZoneOffset.UTC), match.group("user"), match.group("ip"), ActionType.LOGIN, accepted ? StatusCode.SUCCESS : StatusCode.FAILURE, line));
            }
            match = COMMON.matcher(line);
            if (match.matches()) return Optional.of(entry(java.time.OffsetDateTime.parse(match.group("timestamp"), COMMON_TIME).toInstant(), match.group("user"), match.group("ip"), ActionType.from(match.group("method")), StatusCode.from(match.group("status")), line));
        } catch (DateTimeParseException | IllegalArgumentException ignored) { /* represented by Optional.empty */ }
        return Optional.empty();
    }

    public LogFormat detectFormat(String line) {
        if (line == null) return LogFormat.UNKNOWN;
        if (APPLICATION.matcher(line).matches()) return LogFormat.APPLICATION;
        if (SYSLOG.matcher(line).matches()) return LogFormat.SYSLOG_AUTH;
        if (COMMON.matcher(line).matches()) return LogFormat.COMMON;
        return LogFormat.UNKNOWN;
    }

    private LogEntry entry(Instant timestamp, String user, String ip, ActionType action, StatusCode status, String raw) {
        return new LogEntry(timestamp, user, ip, action, status, raw);
    }
}

package com.forensics.loganalyzer.parsing;

import com.forensics.loganalyzer.model.LogEntry;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Reads recent events directly from Windows event channels (Security, System, Application). */
public final class WindowsSecurityLogReader {
    private static final Pattern EVENT_FRAGMENT = Pattern.compile("(?s)<Event(?:\\s[^>]*)?>.*?</Event>");
    private static final String LOGON_QUERY = "/q:*[System[(EventID=4624 or EventID=4625)]]";
    private final WindowsEventXmlParser parser;
    private final LogValidator validator;

    public WindowsSecurityLogReader() { this(new WindowsEventXmlParser(), new LogValidator()); }
    public WindowsSecurityLogReader(WindowsEventXmlParser parser, LogValidator validator) { this.parser = parser; this.validator = validator; }

    /** Reads the newest {@code maximumEvents} from Windows event channels. */
    public LogReadResult readLatest(int maximumEvents) throws IOException {
        if (maximumEvents < 1 || maximumEvents > 1_000) throw new IllegalArgumentException("maximumEvents must be between 1 and 1000");
        if (!System.getProperty("os.name").toLowerCase().contains("win")) throw new IOException("Windows logs are only available on Windows.");

        // 1. Try reading Security channel first (if running with Administrator privileges)
        try {
            Process process = new ProcessBuilder("wevtutil", "qe", "Security", LOGON_QUERY, "/f:xml", "/c:" + maximumEvents, "/rd:true")
                    .redirectErrorStream(true).start();
            String output = drainProcess(process, 10);
            if (process.exitValue() == 0 && output != null && output.contains("<Event")) {
                LogReadResult res = convert(output);
                if (!res.entries().isEmpty()) return res;
            }
        } catch (Exception ignored) {}

        // 2. Read live events from System channel (accessible to ALL users, no Admin required!)
        try {
            Process process = new ProcessBuilder("wevtutil", "qe", "System", "/f:xml", "/c:" + maximumEvents, "/rd:true")
                    .redirectErrorStream(true).start();
            String output = drainProcess(process, 10);
            if (process.exitValue() == 0 && output != null && output.contains("<Event")) {
                return convert(output);
            }
        } catch (Exception ignored) {}

        // 3. Read live events from Application channel
        Process process = new ProcessBuilder("wevtutil", "qe", "Application", "/f:xml", "/c:" + maximumEvents, "/rd:true")
                .redirectErrorStream(true).start();
        String output = drainProcess(process, 10);
        if (process.exitValue() == 0 && output != null && output.contains("<Event")) {
            return convert(output);
        }

        throw new IOException("Could not read Windows Event channels.");
    }

    private static String drainProcess(Process process, int timeoutSeconds) throws IOException {
        CompletableFuture<byte[]> outputBytes = CompletableFuture.supplyAsync(() -> {
            try { return process.getInputStream().readAllBytes(); }
            catch (IOException exception) { throw new CompletionException(exception); }
        });
        try {
            if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return "";
            }
            return new String(outputBytes.join(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            process.destroyForcibly();
            return "";
        }
    }

    private LogReadResult convert(String output) {
        List<LogEntry> entries = new ArrayList<>();
        List<ParseError> errors = new ArrayList<>();
        Matcher matcher = EVENT_FRAGMENT.matcher(output);
        long number = 0;
        while (matcher.find()) {
            number++;
            String xml = matcher.group();
            var candidate = parser.parse(xml);
            if (candidate.isEmpty()) continue;
            ValidationResult validation = validator.validate(candidate.get());
            if (validation.entry().isPresent()) entries.add(validation.entry().get());
            else errors.add(new ParseError(number, xml, validation.error().orElse("Invalid Windows logon event")));
        }
        Map<LogFormat, Long> formats = new EnumMap<>(LogFormat.class);
        formats.put(LogFormat.WINDOWS_EVTX, number);
        return new LogReadResult(entries, errors, StandardCharsets.UTF_8, formats);
    }
}
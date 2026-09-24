package com.forensics.loganalyzer.parsing;

import com.forensics.loganalyzer.model.LogEntry;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads an exported Windows {@code .evtx} file through the built-in Windows {@code wevtutil}
 * utility. It supports Security logon events 4624 (success) and 4625 (failure).
 */
public final class EvtxLogReader {
    private static final Pattern EVENT_FRAGMENT = Pattern.compile("(?s)<Event(?:\\s[^>]*)?>.*?</Event>");
    private final WindowsEventXmlParser parser;
    private final LogValidator validator;

    public EvtxLogReader() { this(new WindowsEventXmlParser(), new LogValidator()); }
    public EvtxLogReader(WindowsEventXmlParser parser, LogValidator validator) { this.parser = parser; this.validator = validator; }

    public LogReadResult readWithReport(Path evtxFile) throws IOException {
        if (!System.getProperty("os.name").toLowerCase().contains("win")) {
            throw new IOException("EVTX files require Windows and its built-in wevtutil utility.");
        }
        Process process = new ProcessBuilder("wevtutil", "qe", evtxFile.toAbsolutePath().toString(), "/lf:true", "/f:xml")
                .redirectErrorStream(true).start();
        String output;
        try {
            if (!process.waitFor(60, TimeUnit.SECONDS)) { process.destroyForcibly(); throw new IOException("Timed out while reading EVTX file."); }
            output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while reading EVTX file.", exception);
        }
        if (process.exitValue() != 0) throw new IOException("wevtutil could not read the EVTX file: " + output.strip());

        List<LogEntry> entries = new ArrayList<>();
        List<ParseError> errors = new ArrayList<>();
        Matcher matcher = EVENT_FRAGMENT.matcher(output);
        long number = 0;
        while (matcher.find()) {
            number++;
            String xml = matcher.group();
            var candidate = parser.parse(xml);
            if (candidate.isEmpty()) continue; // unrelated Windows event, not an error
            ValidationResult validation = validator.validate(candidate.get());
            if (validation.entry().isPresent()) entries.add(validation.entry().get());
            else errors.add(new ParseError(number, xml, validation.error().orElse("Invalid Windows logon event")));
        }
        Map<LogFormat, Long> formats = new EnumMap<>(LogFormat.class);
        formats.put(LogFormat.WINDOWS_EVTX, number);
        return new LogReadResult(entries, errors, StandardCharsets.UTF_8, formats);
    }
}

package com.forensics.loganalyzer.parsing;

import com.forensics.loganalyzer.model.LogEntry;
import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/** Buffered, one-pass reader suitable for historical log files of arbitrary size. */
public final class LogReader {
    private final LogParser parser;
    private final LogValidator validator;

    public LogReader() { this(new LogParser(), new LogValidator()); }
    public LogReader(LogParser parser, LogValidator validator) { this.parser = parser; this.validator = validator; }

    /** Convenience method when only parsed events are needed. */
    public List<LogEntry> read(Path path) throws IOException { return readWithReport(path).entries(); }

    public LogReadResult readWithReport(Path path) throws IOException {
        Charset charset = detectEncoding(path);
        List<LogEntry> entries = new ArrayList<>();
        List<ParseError> errors = new ArrayList<>();
        Map<LogFormat, Long> formats = new EnumMap<>(LogFormat.class);
        try (BufferedReader reader = Files.newBufferedReader(path, charset)) {
            String line; long lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                // Java's UTF-8 decoder exposes a BOM as U+FEFF; it is not part of the log record.
                if (lineNumber == 1 && !line.isEmpty() && line.charAt(0) == '\uFEFF') line = line.substring(1);
                LogFormat format = parser.detectFormat(line);
                formats.merge(format, 1L, Long::sum);
                var parsed = parser.parse(line);
                if (parsed.isEmpty()) { errors.add(new ParseError(lineNumber, line, "Unrecognized or malformed log line")); continue; }
                ValidationResult validation = validator.validate(parsed.get());
                if (validation.entry().isPresent()) entries.add(validation.entry().get());
                else errors.add(new ParseError(lineNumber, line, validation.error().orElse("Invalid log entry")));
            }
        }
        return new LogReadResult(entries, errors, charset, formats);
    }

    private Charset detectEncoding(Path path) throws IOException {
        byte[] prefix;
        try (var input = Files.newInputStream(path)) { prefix = input.readNBytes(3); }
        if (prefix.length >= 3 && prefix[0] == (byte) 0xEF && prefix[1] == (byte) 0xBB && prefix[2] == (byte) 0xBF) return StandardCharsets.UTF_8;
        if (prefix.length >= 2 && prefix[0] == (byte) 0xFF && prefix[1] == (byte) 0xFE) return StandardCharsets.UTF_16LE;
        if (prefix.length >= 2 && prefix[0] == (byte) 0xFE && prefix[1] == (byte) 0xFF) return StandardCharsets.UTF_16BE;
        return StandardCharsets.UTF_8;
    }
}

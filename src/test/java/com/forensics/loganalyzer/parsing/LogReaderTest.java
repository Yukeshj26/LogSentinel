package com.forensics.loganalyzer.parsing;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class LogReaderTest {
    @Test void returnsEntriesAndAuditableErrors() throws Exception {
        Path file = Files.createTempFile("logs", ".log");
        Files.writeString(file, "2026-07-24T10:15:30Z INFO user=jane ip=192.168.1.10 action=LOGIN status=200\ninvalid\n2026-07-24T10:15:30Z INFO user=bad! ip=192.168.1.10 action=LOGIN status=200\n", StandardCharsets.UTF_8);
        LogReadResult result = new LogReader().readWithReport(file);
        assertEquals(1, result.entries().size()); assertEquals(2, result.errors().size()); assertEquals(2, result.errors().get(0).lineNumber()); assertEquals(3, result.errors().get(1).lineNumber()); assertEquals(StandardCharsets.UTF_8, result.charset());
    }
    @Test void acceptsIpv6AndRejectsUnknownAction() throws Exception {
        Path file = Files.createTempFile("logs", ".log");
        Files.writeString(file, "2026-07-24T10:15:30Z INFO user=alice ip=2001:db8::1 action=LOGIN status=SUCCESS\n2026-07-24T10:15:30Z INFO user=bob ip=192.0.2.1 action=OTHER status=200\n");
        LogReadResult result = new LogReader().readWithReport(file);
        assertEquals(1, result.entries().size());
        assertEquals("Unknown action", result.errors().get(0).reason());    }
}

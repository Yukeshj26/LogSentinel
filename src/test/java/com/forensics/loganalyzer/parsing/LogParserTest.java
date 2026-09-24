package com.forensics.loganalyzer.parsing;

import com.forensics.loganalyzer.model.ActionType;
import com.forensics.loganalyzer.model.StatusCode;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class LogParserTest {
    private final LogParser parser = new LogParser(Clock.fixed(Instant.parse("2026-07-24T00:00:00Z"), ZoneOffset.UTC));

    @Test void parsesApplicationLog() {
        var entry = parser.parse("2026-07-24T10:15:30Z INFO user=jane ip=192.168.1.10 action=LOGIN status=200").orElseThrow();
        assertEquals("jane", entry.username()); assertEquals(ActionType.LOGIN, entry.action()); assertEquals(StatusCode.SUCCESS, entry.statusCode());
    }
    @Test void parsesFailedSshAuthLog() {
        var entry = parser.parse("Jul 24 10:15:30 server sshd[42]: Failed password for invalid user admin from 203.0.113.10 port 22 ssh2").orElseThrow();
        assertEquals("admin", entry.username()); assertEquals(StatusCode.FAILURE, entry.statusCode());
    }
    @Test void parsesCommonLogFormat() {
        var entry = parser.parse("192.0.2.5 - bob [24/Jul/2026:10:15:30 +0000] \"POST /login HTTP/1.1\" 401 213").orElseThrow();
        assertEquals(ActionType.CREATE, entry.action()); assertEquals(StatusCode.UNAUTHORIZED, entry.statusCode());
    }
    @Test void rejectsBlankAndMalformedLines() { assertTrue(parser.parse(" ").isEmpty()); assertTrue(parser.parse("nonsense").isEmpty()); }
    @Test void detectsFormats() { assertEquals(LogFormat.APPLICATION, parser.detectFormat("2026-07-24T10:15:30Z INFO user=a ip=192.0.2.1 action=LOGIN status=200")); assertEquals(LogFormat.UNKNOWN, parser.detectFormat("bad")); }
}

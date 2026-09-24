package com.forensics.loganalyzer.parsing;

import com.forensics.loganalyzer.model.StatusCode;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class WindowsEventXmlParserTest {
    private final WindowsEventXmlParser parser = new WindowsEventXmlParser();

    @Test void convertsFailedWindowsLogon() {
        var entry = parser.parse("""
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                  <System><EventID>4625</EventID><TimeCreated SystemTime="2026-07-25T04:00:00.000Z"/></System>
                  <EventData><Data Name="TargetUserName">admin</Data><Data Name="IpAddress">203.0.113.10</Data></EventData>
                </Event>
                """).orElseThrow();
        assertEquals("admin", entry.username());
        assertEquals("203.0.113.10", entry.ipAddress());
        assertEquals(StatusCode.FAILURE, entry.statusCode());
    }

    @Test void ignoresUnrelatedWindowsEvent() {
        assertTrue(parser.parse("<Event xmlns=\"urn:test\"><System><EventID>1000</EventID></System></Event>").isEmpty());
    }
}

package com.forensics.loganalyzer.parsing;

import com.forensics.loganalyzer.model.ActionType;
import com.forensics.loganalyzer.model.LogEntry;
import com.forensics.loganalyzer.model.StatusCode;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/** Converts Windows Event XML from Security, System, and Application logs into {@link LogEntry} values. */
public final class WindowsEventXmlParser {
    private static final String UNKNOWN_IP = "127.0.0.1";

    public Optional<LogEntry> parse(String eventXml) {
        try {
            Document document = secureFactory().newDocumentBuilder().parse(
                    new ByteArrayInputStream(eventXml.getBytes(StandardCharsets.UTF_8)));

            Element timeCreated = firstElement(document, "TimeCreated");
            if (timeCreated == null || !timeCreated.hasAttribute("SystemTime")) return Optional.empty();
            Instant timestamp = Instant.parse(timeCreated.getAttribute("SystemTime"));

            int eventId = 0;
            try { eventId = Integer.parseInt(text(document, "EventID")); } catch (Exception ignored) {}

            int level = 4;
            try { level = Integer.parseInt(text(document, "Level")); } catch (Exception ignored) {}

            Map<String, String> fields = eventData(document);

            Element providerEl = null;
            try { providerEl = firstElement(document, "Provider"); } catch (Exception ignored) {}
            String provider = (providerEl != null && providerEl.hasAttribute("Name")) ? providerEl.getAttribute("Name") : "System";

            String username = usable(fields.get("TargetUserName"), null);
            if (username == null) username = usable(fields.get("SubjectUserName"), null);
            if (username == null) username = usable(fields.get("User"), null);
            if (username == null) username = provider;

            String ipAddress = usableIp(fields.get("IpAddress"));
            if ("0.0.0.0".equals(ipAddress) || ipAddress.isBlank()) {
                ipAddress = UNKNOWN_IP;
            }

            ActionType action;
            StatusCode status;

            if (eventId == 4624) {
                action = ActionType.LOGIN;
                status = StatusCode.SUCCESS;
            } else if (eventId == 4625) {
                action = ActionType.LOGIN;
                status = StatusCode.FAILURE;
            } else if (eventId == 4634 || eventId == 4647) {
                action = ActionType.LOGOUT;
                status = StatusCode.SUCCESS;
            } else if (level == 1 || level == 2) {
                action = ActionType.EXECUTE;
                status = StatusCode.FAILURE;
            } else if (level == 3) {
                action = ActionType.UPDATE;
                status = StatusCode.UNAUTHORIZED;
            } else {
                action = ActionType.EXECUTE;
                status = StatusCode.SUCCESS;
            }

            return Optional.of(new LogEntry(timestamp, username, ipAddress, action, status, eventXml));
        } catch (Exception ignored) {
            return Optional.empty();
        }
    }

    private static DocumentBuilderFactory secureFactory() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setExpandEntityReferences(false);
        factory.setXIncludeAware(false);
        factory.setNamespaceAware(true);
        return factory;
    }

    private static Map<String, String> eventData(Document document) {
        Map<String, String> values = new HashMap<>();
        NodeList nodes = document.getElementsByTagNameNS("*", "Data");
        for (int index = 0; index < nodes.getLength(); index++) {
            Element data = (Element) nodes.item(index);
            values.put(data.getAttribute("Name"), data.getTextContent().trim());
        }
        return values;
    }

    private static String text(Document document, String name) { return firstElement(document, name).getTextContent().trim(); }
    private static Element firstElement(Document document, String name) {
        NodeList elements = document.getElementsByTagNameNS("*", name);
        if (elements.getLength() == 0) throw new IllegalArgumentException("Missing XML element: " + name);
        return (Element) elements.item(0);
    }
    private static String usable(String value, String fallback) { return value == null || value.isBlank() || value.equals("-") ? fallback : value; }
    private static String usableIp(String value) { return usable(value, UNKNOWN_IP); }
}
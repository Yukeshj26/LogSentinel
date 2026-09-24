# LogSentinel — Real-Time Cybersecurity Log Analyzer & Threat Detection System

LogSentinel is an automated cybersecurity log analysis and digital forensics platform built with Java 17 and Spring Boot. It continuously monitors security event streams (including live Windows Security and System Event channels), performs real-time threat detection, and provides an interactive web dashboard with Server-Sent Events (SSE).

---

## Features

- **Live Windows Security Log Monitoring**: Real-time polling of Windows Security event channels (Event IDs 4624 Logon, 4625 Failed Logon, 4634/4647 Logoff) via `wevtutil`, with graceful non-admin fallback to the System/Application channels.
- **Real-Time Streaming Threat Detection**:
  - `BRUTE_FORCE`: $\ge$ 5 failed logins from one IP within 60 seconds (Escalates to CRITICAL).
  - `REPEATED_LOGIN_FAILURE`: $\ge$ 3 login failures from one IP within 10 minutes.
  - `UNAUTHORIZED_ACCESS`: Any single denied-access event.
  - `ANOMALOUS_BEHAVIOR`: Single user account authenticating across $\ge$ 3 distinct IP addresses.
- **Rolling Buffer & Incident Deduplication**: `StreamingThreatDetector` retains an active time-window buffer to catch multi-packet distributed attacks across polling intervals without duplicate alerts.
- **Interactive Web Dashboard**:
  - Real-time telemetry feed via Server-Sent Events (SSE).
  - Live security KPI metrics: total events, threats, login failures, and active buffer.
  - Interactive threat filtering by severity (LOW / MEDIUM / HIGH / CRITICAL).
  - Drag-and-drop file upload and in-browser raw text log analysis drawer.
  - One-click privilege elevation launcher for Windows Security event access.
- **Multi-Format Parsing**:
  - Windows Event XML (`evtx` / `wevtutil`)
  - Key-value format (`timestamp IP=... USER=... ACTION=... STATUS=...`)
  - Linux `sshd` auth syslog format

---

## Architecture & Project Layout

```
loganalyzer/
 ├── pom.xml                                  Maven configuration (Java 17, Spring Boot 3.3.4)
 ├── run-admin.bat                            Elevated launch script for Windows Security log access
 ├── Start-LogSentinel-Admin.lnk              Desktop/Explorer shortcut for admin execution
 ├── incident_sample.log                      Sample security incident log
 ├── sample.log                               Basic sample log
 └── src/
      ├── main/
      │    ├── java/com/forensics/loganalyzer/
      │    │    ├── LogAnalyzerApplication.java   Spring Boot application entry point
      │    │    ├── api/                          REST controllers, DTOs & SSE live monitor service
      │    │    ├── detection/                    Streaming & batch threat detection, risk scoring
      │    │    ├── model/                        Domain models (LogEntry, ActionType, StatusCode, SeverityLevel)
      │    │    └── parsing/                      Windows EVTX/XML, syslog, and key-value parsers + validator
      │    └── resources/
      │         ├── application.properties        Server & logging configuration
      │         └── static/                       Web dashboard (index.html, style.css, app.js)
      └── test/
           └── java/com/forensics/loganalyzer/    Unit & integration tests
```

---

## Quick Start

### Prerequisites
- **Java 17+** (JDK 17 or higher)
- **Maven 3.8+** (or pre-built JAR)

### 1. Build the Application
```bash
mvn clean package
```
This produces `target/log-analyzer-1.0.0.jar`.

### 2. Run the Application

#### Standard Mode (All OS / Non-Admin)
```bash
java -jar target/log-analyzer-1.0.0.jar
```
Access the web dashboard at: **[http://localhost:8080](http://localhost:8080)**

#### Administrator Mode (Windows Live Security Log Access)
Windows requires Administrator privileges to read the `Security` event log channel.
- Right-click `run-admin.bat` and select **"Run as administrator"**, or
- Double-click `Start-LogSentinel-Admin.lnk`.

---

## REST API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/stream` | `GET` | SSE stream for real-time log events, threats, and stats |
| `/api/status` | `GET` | Current session statistics and privileges |
| `/api/analyze` | `POST` | Multipart file upload for one-shot log analysis |
| `/api/analyze/text` | `POST` | Raw text payload analysis |
| `/api/admin/status` | `GET` | Diagnostic check for Windows admin privileges |
| `/api/admin/elevate` | `POST` | Triggers Windows UAC elevation flow |

---

## License
MIT License.

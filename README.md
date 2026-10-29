# CyberShield — Security Event Monitor

CyberShield is a small Java 17 defensive-security project. It accepts simulated login events, detects repeated failed logins from the same IP address, and creates alerts for staff to review.

## Features

- REST API built with Javalin
- Detection of three failed logins from the same IP within five minutes
- HIGH-severity alerts, event history, and alert resolution
- API-key protection for staff endpoints and administrator-only alert resolution
- Unit tests for detection and validation
- Health endpoint for quick checks

## Requirements

- Java 17 or newer
- Maven 3.6+

## Run

```bash
mvn test
mvn package
java -jar target/cybershield-1.0.0.jar
```

The app listens on port `7070` by default. For local learning only, development keys are supplied as defaults. Override them before running:

```bash
export CYBERSHIELD_STAFF_KEY='replace-with-a-long-random-staff-key'
export CYBERSHIELD_ADMIN_KEY='replace-with-a-different-long-random-admin-key'
export PORT=7070
mvn exec:java -Dexec.mainClass=za.co.cybershield.App
```

The `exec:java` command requires Maven's exec plugin; alternatively run the packaged application with the environment variables set. Never use the development defaults outside a local demo.

## API examples

Set a local variable for the development staff key:

```bash
STAFF_KEY='dev-staff-key-change-me'
ADMIN_KEY='dev-admin-key-change-me'
```

Health check (no key required):

```bash
curl http://localhost:7070/health
```

Record a failed login:

```bash
curl -X POST http://localhost:7070/api/events \
  -H "X-API-Key: $STAFF_KEY" -H 'Content-Type: application/json' \
  -d '{"username":"alex","sourceIp":"192.0.2.10","type":"LOGIN_FAILURE"}'
```

Repeat that request three times from the same IP to trigger an alert. The example IP uses the documentation-only range `192.0.2.0/24`.

View events and alerts:

```bash
curl -H "X-API-Key: $STAFF_KEY" http://localhost:7070/api/events
curl -H "X-API-Key: $STAFF_KEY" http://localhost:7070/api/alerts
```

Resolve alert 1 (admin only):

```bash
curl -X POST -H "X-API-Key: $ADMIN_KEY" http://localhost:7070/api/alerts/1/resolve
```

## Endpoints

| Method | Path | Access | Purpose |
|---|---|---|---|
| GET | `/health` | Public | Health status |
| POST | `/api/events` | Staff or admin key | Record a login event |
| GET | `/api/events` | Staff or admin key | List recorded events |
| GET | `/api/alerts` | Staff or admin key | List alerts |
| POST | `/api/alerts/{id}/resolve` | Admin key | Resolve an alert |

## Project structure

```text
cybershield/
├── README.md
├── SECURITY.md
├── pom.xml
└── src/
    ├── main/java/za/co/cybershield/
    │   ├── App.java
    │   ├── SecurityAlert.java
    │   ├── SecurityEvent.java
    │   └── SecurityMonitor.java
    └── test/java/za/co/cybershield/
        └── SecurityMonitorTest.java
```

## Scope and limitations

This is an educational demo using in-memory storage. Events and alerts disappear when the app restarts. It does not connect to real login systems, block IP addresses, or replace a production SIEM. Before production use, add persistent storage, TLS, key rotation, rate limiting, audit protections, and stronger operational controls.

Verification code: WTC-FYV97YQR
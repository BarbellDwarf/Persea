# Ticket: Audit Logging

wayfinder:research
Blocked by: 003 (Auth DB Schema), 009 (User Identity Model)

## Question

How should persea implement enterprise audit logging?

SOC 2 Type II, NIST 800-53 (AU-2, AU-3), and HIPAA all require structured audit logs. Every auth attempt, session, connection, and admin action must be logged.

Key decisions needed:

1. **Event categories** — Auth (login success/failure, MFA challenges, lockouts), Session (start/end, idle timeout), Connection (attempt, success, fail, source IP, target, protocol, duration), Admin (user create/delete, role changes, config changes), File transfer (upload/download).
2. **Log structure** — Each event: event_type, timestamp (UTC), user_id, source_ip, outcome (success/failure), details (JSON), session_id.
3. **Tamper evidence** — Hash chain: each event includes hash of previous event. Tampering breaks the chain.
4. **Storage** — SQLite/MySQL/PostgreSQL table. Optional syslog forwarding for SIEM.
5. **Retention** — Configurable. Default 90 days. SOC 2 requires 1 year minimum.
6. **Query API** — Admin endpoint to query audit events with filters (user, date range, event type).
7. **Export** — CSV/JSON export for compliance reporting.
8. **SIEM integration** — Syslog (CEF or LEEF format) or structured JSON to external logger.
9. **Session recording** — Existing `.guac` format. Audit log references recording files.

## Research needed

- NIST AU-2/AU-3 audit event requirements
- SOC 2 CC7 monitoring requirements
- Apache Guacamole's audit logging (connection_history, user_history)
- Syslog CEF/LEEF format for SIEM integration

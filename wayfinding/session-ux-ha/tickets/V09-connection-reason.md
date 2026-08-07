# Ticket: Connection reason field (admin-toggleable)

wayfinder:grilling
Priority: P2

## Question

When connecting to a session, the user should be able to input a reason for the connection (e.g. "password rotation", "maintenance", "troubleshooting"). This reason is stored with the audit information and is admin-toggleable.

## Design questions

1. Where does the reason prompt appear — before the session starts (modal) or after (toolbar input)?
2. Is it mandatory or optional? (Admin config: mandatory, optional, disabled)
3. Where is the reason stored — session_history table (new column), audit_events, or a separate table?
4. Who can see the reason — admins only, or the user themselves on their sessions page?
5. Is the reason pre-filled from a dropdown of common reasons, or free text?

## Deliverable

A grilling session resolving these questions, with the chosen design spec.

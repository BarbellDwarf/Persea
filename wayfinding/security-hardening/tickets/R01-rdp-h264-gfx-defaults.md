# Ticket: Enable H.264 and GFX by default for RDP

wayfinder:task
Priority: P2

## Question

RDP sessions default to `enable_h264: false` and `enable_gfx: false` (`create.rs:334,344`). This forces JPEG/PNG tile rendering (5-15ms/frame slower than H.264) and disables RemoteFX/ProGFX optimizations. H.264 uses WebCodecs GPU decode (0.5-3ms vs 5-20ms CPU decode for JPEG).

Flip both defaults to `true` in the `CreateSessionRequest` defaults. This affects all new RDP sessions — existing sessions are unaffected. VDI sessions already have these enabled. The entry form should expose the toggle so admins can override per-entry.

## Deliverable

Updated `create.rs` defaults. New RDP sessions use H.264 + GFX. Entry modal has optional "Enable graphics pipeline" and "Enable H.264" checkboxes for RDP type. All RDP tests pass.

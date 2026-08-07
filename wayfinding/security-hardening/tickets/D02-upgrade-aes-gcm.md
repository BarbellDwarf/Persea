# Ticket: Upgrade aes-gcm (MEDIUM CVE)

wayfinder:task
Priority: P0

## Question

aes-gcm 0.11.0 has RUSTSEC-2023-0096: plaintext is exposed in `decrypt_in_place_detached` even when tag verification fails. persea uses aes-gcm for credential encryption (AES-256-GCM).

Upgrade aes-gcm to the latest patched 0.11.x or newer. Verify `cargo audit` clears. Run `cargo test` to confirm encryption/decryption round-trips still work.

## Deliverable

Updated Cargo.lock. Zero aes-gcm advisories. All crypto tests pass.

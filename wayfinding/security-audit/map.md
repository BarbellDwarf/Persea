# Map: Security Audit Remediation

## Destination

Close all findings from the full security audit. 3 Critical + 8 High + 7 Medium + 5 Low findings across auth, admin UI, infrastructure trust boundaries, and hardening gaps.

## Notes

- Cross-references existing `security-hardening/` tickets where overlap exists (S01, S02, S03, S05).
- New tickets numbered C01-C03 (Critical), H01-H08 (High), M01-M07 (Medium), L01-L05 (Low).
- Each ticket has file:line references and fix guidance so a coding agent can act independently.
- Findings 4/5/7/14 overlap with existing security-hardening S01/S02/S03/S05 — those tickets are already resolved on 1.1.0. Verify they actually fixed the issue before skipping.

## Decisions so far

- **Overlap strategy**: Findings already covered by resolved S01/S02/S03/S05 tickets will be verified (not re-created). New tickets only for genuinely new findings.
- **Phase ordering**: Critical first, then High, then Medium, then Low. Each phase can have parallel subagents for disjoint files.

## Not yet specified

(none — all findings documented)

## Out of scope

- Full penetration test
- Infrastructure hardening outside persea's repo (Docker/OS level)
- Dependency CVE triage (covered by security-hardening D01-D05)

## Reviewed — no issue found

These were investigated and confirmed safe. Do not re-investigate:

- `src/rbac.rs` recursive CTE group-cycle — no reachable path to create a cycle
- `src/api/address_book.rs` folder-prefix ACL — consistent trailing `/` before `starts_with`
- `src/vdi/docker.rs` — no privileged, resource limits, nosuid/nodev, path-traversal guard
- `src/vsphere.rs` host-level SSRF — config-only, TLS defaults on, password env-only
- `src/session/mod.rs` — constant-time token comparison, correct IDOR scoping
- `src/websocket.rs` — correct CSWSH origin validation
- `src/oidc.rs` — PKCE + nonce + CSRF state, open-redirect guard, correct cookie flags

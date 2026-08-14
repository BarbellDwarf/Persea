# guacamole-server patches (moved to a fork)

The former patch quilt (FreeRDP 3.x / Debian 13 compile fixes, RDP Kerberos
NLA, H.264 passthrough, SPICE protocol, RDP multi-monitor) is now maintained
as ordinary commits on the persea fork of guacamole-server:

- **Fork:** https://github.com/persea-grove/persea-guacamole-server
- **Branch:** `persea-1.6.1-freerdp3` — a fork of apache/guacamole-server at
  the pinned base commit `de97609`, with one commit per former patch, each
  citing the original patch and upstream issue.

All build scripts (`Dockerfile`, `install.sh`, `build-deb.sh`,
`build-rpm.sh`) clone the fork branch directly — there is no patch-application
step anymore. For local development, check out the fork branch at
`../guacamole-server` (see `dev.sh`).

To add or update a fix: commit it on the fork branch (one commit per fix,
message citing the motivating issue), push it, and note the branch reference
in `AGENTS.md` build notes.

# Subagent Work Contract

**Applies to:** every implementation subagent dispatched in this repo.
**Reference:** `AGENTS.md` → "Subagent Work Contract" section.

## Tickets

GitHub issues are the source of truth. Every subagent works from an open
issue (see `AGENTS.md` → "Issue tracking"). Reference the issue in the
commit message (`fix: ... (repo#N)`); use `Closes #N` in the PR body to
close it on merge.

## Model: Edits first, single verifier

Parallel subagents do NOT build concurrently. Cargo serializes builds via the
`target/` lock, so N parallel `cargo check` runs queue and slow each other
down, and concurrent `git add`/`commit` contend on `.git/index.lock`
(which has already wiped an agent's work once in this project).

Instead:

1. **Subagents edit files and commit immediately**: no `cargo check`, no
   `cargo test`, no `cargo fmt` inside the subagent. Fast edits, fast
   commits, minimal git contention.
2. **A single verification pass runs AFTER all subagents land**: the
   dispatcher runs `cargo check` + `cargo test` + `cargo fmt --check` once
   and fixes any issues. One build instead of N queued builds.
3. **Subagents work on disjoint files only**: no two agents touch the same
   file, so a broken commit is isolated and fixed in the verification pass.

## Mandatory rules for subagents

1. **Commit your work.** Never leave uncommitted changes. If interrupted,
   commit partial work with a `WIP:` message. Uncommitted work is lost work.
2. **Never run `git reset`, `git checkout .`, or `git stash`.** These destroy
   other agents' parallel work. If the tree has unexpected changes, leave
   them alone and work around them.
3. **Never modify files outside your ticket's scope.** If you need a file
   another agent is touching, stop and report the conflict.
4. **Report back** after committing: commit hash, files changed, anything
   unusual you observed in the tree.

## Mandatory rules for the dispatcher (verification pass)

After all subagents in a batch land:

1. `cargo check`: must pass with 0 errors
2. `cargo test`: must pass. Fix any NEW failures introduced by the batch.
   Pre-existing failures (unrelated to the batch) are noted, not fixed.
3. `cargo fmt --check`: must pass. Run `cargo fmt` if not.
4. `git status`: confirm only intended files changed; commit any strays.
5. Push, then check CI (`gh run list`): CI must be green before moving on.

## Why this exists

Subagents that ran `cargo check` only shipped changes that broke
`cargo test` (missing imports in test code), `cargo fmt --check`
(unformatted code), and left uncommitted WIP. Parallel builds also
serialized on the cargo lock and contended on the git index. This contract
prevents those failures and keeps parallel work fast.

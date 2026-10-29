# Security and Functionality Code Review

**Review date:** 2026-10-29  
**Scope:** Current working-tree diff; existing reports under `code-reviews/` were excluded.

## Summary

The diff changes only the executable mode of four packaging scripts; it contains no source-line changes. Those mode changes break the documented direct invocations and prevent the LXD deploy script from running its build step. No security vulnerability was identified in the changed code. The web interface access-control policy is unchanged; this review does not recommend adding authentication.

This is a diff-scoped review, not a full security audit of the repository. No tests were run.

## Findings

### 1. Packaging scripts are no longer executable

- **Severity:** Medium
- **Confidence:** 10/10
- **Affected files:** `packaging/deploy-lxd.sh`, `packaging/rk3588s/build-rk3588s.sh`, `packaging/standalone/build-standalone.sh`, `packaging/unikernel/build-unikernel.sh`
- **Location:** Mode changes (no source-line changes); `packaging/deploy-lxd.sh:18` also invokes the build script directly.
- **Evidence:** The working-tree diff changes all four scripts from mode `100755` to `100644`. The README documents direct `./packaging/...` invocations (for example, lines 366, 379, 399, 419, and 434), and `deploy-lxd.sh:18` runs `./packaging/unikernel/build-unikernel.sh`.
- **Impact:** On Unix-like systems, documented direct invocations fail with a permission error. Directly invoking `deploy-lxd.sh` fails as well; if run through a shell, its build step still fails because `build-unikernel.sh` is not executable.
- **Recommendation:** Restore executable mode (`100755`) on all four scripts, or consistently invoke them through `bash` and update the documented commands.

## Security notes

No security-sensitive source changes are present in this diff, so no changed-code vulnerability was found. The web interface access-control design was not altered or assessed as part of this diff review; no authentication-fronting change is proposed.

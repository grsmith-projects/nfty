# Security Review

**Review date:** 2026-10-29  
**Scope:** Current working-tree diff. Existing review reports under `code-reviews/` were excluded.

## Summary

The diff contains no source-line changes; it changes the executable mode of four packaging scripts. This causes a functional regression in documented packaging and deployment commands. No security vulnerability was identified in the changed code. The web interface access-control policy is unchanged, and this review does not recommend adding authentication.

This is a diff-scoped review, not a full security audit of the repository. No tests were run.

## Finding

### Medium — Packaging scripts are no longer executable

- **Confidence:** 10/10
- **Affected files:** `packaging/deploy-lxd.sh`, `packaging/rk3588s/build-rk3588s.sh`, `packaging/standalone/build-standalone.sh`, `packaging/unikernel/build-unikernel.sh`
- **Location:** Mode changes (no source-line changes); `packaging/deploy-lxd.sh:18` invokes the build script directly.
- **Evidence:** All four scripts changed from mode `100755` to `100644`. The README documents direct `./packaging/...` invocations (including lines 366, 379, 399, 419, and 434), while `deploy-lxd.sh:18` runs `./packaging/unikernel/build-unikernel.sh`.
- **Impact:** On Unix-like systems, documented direct invocations fail with a permission error. Invoking `deploy-lxd.sh` through a shell does not avoid the failure because its build step also directly executes the non-executable build script.
- **Recommendation:** Restore executable mode (`100755`) on all four scripts, or consistently invoke them through `bash` and update the documentation.

## Security notes

No security-sensitive source changes are present in this diff. The web interface allow-list design was not altered or assessed as part of this diff review; no authentication-fronting change is proposed.

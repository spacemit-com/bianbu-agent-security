# Syscall Policy and Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add administrator-managed, versioned syscall denylist additions, execution status, and independent interception audit without changing FR-SEC-05 blocking semantics.

**Architecture:** securityd owns policy storage and D-Bus methods. Existing seccomp builder consumes the merged immutable snapshot at sandbox-policy generation. Runtime exposes status; a separate audit store/backend probe records only deny events and never controls enforcement.

**Tech Stack:** Python 3, dbus-python, SQLite, existing seccomp cBPF builder, Flask WebUI, pytest.

**Spec:** `docs/superpowers/specs/2026-09-04-syscall-policy-audit-design.md`

## Global Constraints

- Preserve `SECCOMP_RET_ERRNO | EPERM` and architecture mismatch kill behavior.
- Mandatory 12 syscall baseline is immutable.
- Only administrators may mutate policies; every mutation is audited.
- Changes apply only to newly started/restarted Workers.
- Audit collection failure must not relax seccomp.

### Task 1: Policy store and merge API

**Files:**
- Create: `impl/bianbu-securityd/securityd/syscall_policy.py`
- Modify: `impl/bianbu-securityd/securityd/config.py`
- Test: `impl/bianbu-securityd/tests/test_syscall_policy.py`

- [ ] Add catalog descriptions, architecture validation, SQLite schema, merge/version/pending logic.
- [ ] Test mandatory immutability, unknown/cross-arch rejection, global+agent merge and reset.
- [ ] Run `pytest impl/bianbu-securityd/tests/test_syscall_policy.py -q`.

### Task 2: Engine and D-Bus contract

**Files:**
- Modify: `impl/bianbu-securityd/securityd/engine.py`
- Modify: `impl/bianbu-securityd/securityd/service.py`
- Modify: `impl/bianbu-securityd/data/io.bianbu.Security.xml`
- Modify: `impl/bianbu-securityd/client/bianbu_security_client.py`
- Test: `impl/bianbu-securityd/tests/test_syscall_dbus_contract.py`

- [ ] Add engine methods with admin checks and mutation audit.
- [ ] Add exact D-Bus methods and client wrappers while retaining BuildSandboxPolicy.
- [ ] Test signatures, errors, and audit calls.

### Task 3: Seccomp snapshot integration

**Files:**
- Modify: `impl/bianbu-securityd/securityd/seccomp_builder.py`
- Modify: `impl/bianbu-securityd/runtime/policy.py`
- Test: `impl/bianbu-securityd/tests/test_seccomp_policy_snapshot.py`

- [ ] Resolve effective denylist per agent/arch before BPF generation.
- [ ] Return policy version metadata and preserve existing paths/actions.
- [ ] Test old/new version behavior and FR-SEC-05 regression.

### Task 4: Independent syscall audit and execution status

**Files:**
- Create: `impl/bianbu-securityd/securityd/syscall_audit.py`
- Modify: `impl/bianbu-securityd/securityd/engine.py`
- Modify: `impl/bianbu-securityd/securityd/service.py`
- Test: `impl/bianbu-securityd/tests/test_syscall_audit.py`

- [ ] Add independent SQLite sequence/hash chain, backend probe and status.
- [ ] Add GetSecurityExecutionStatus and export/verification boundaries.
- [ ] Test unavailable backend and audit-chain isolation.

### Task 5: Runtime status bridge and WebUI

**Files:**
- Modify: `/home/duancheng/workspace/bianbu-agent/bianbu-agent-runtime/bianbu_agent/security/execution_runtime.py`
- Modify: runtime status API and security WebUI assets/routes.
- Test: Runtime status and browser/API integration tests.

- [ ] Surface policy/applied versions, pending restart, sandbox and audit state.
- [ ] Add catalog multi-select and admin-only save/reset UX.
- [ ] Verify dark/light themes and empty/error states.

### Task 6: End-to-end verification

- [ ] Run Security seccomp/sandbox/Hermes regression suite.
- [ ] Run Runtime seccomp/bwrap and full API tests.
- [ ] Run D-Bus contract verifier and isolated sandbox probe.
- [ ] Document results and any platform-specific unavailable audit backend.

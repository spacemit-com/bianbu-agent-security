# Network Allow All And Learning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver `allow_all` and a complete `learning` network mode from Security policy through Runtime capture, query, 9899 UI, Debian packages, and K3 acceptance.

**Architecture:** Security remains authoritative for modes, versions, learning events, and collector status. Runtime compiles the startup boundary, observes only learning Workers through their existing per-instance trace boundary, forwards events with immutable lease identity, and exposes the Security data to the 9899 UI.

**Tech Stack:** Python 3.14, pytest, SQLite, dbus-python, FastAPI, vanilla JavaScript, systemd transient scopes, strace, Debian packaging.

**Spec:** `docs/superpowers/specs/2026-09-07-network-allow-all-learning-design.md`

## Global Constraints

- Supported modes are exactly `whitelist`, `deny_all`, `allow_all`, and `learning`.
- `allow_all` and `learning` produce no `IPAddressDeny` or `IPAddressAllow` properties.
- Learning records destination metadata only; never HTTP/TLS content or credentials.
- Security validates every learning event and status report against a live lease, PID, and cgroup.
- Raw events are retained for 7 days and capped at 5000 per Agent; query limit is 1 through 200.
- The user-facing API and page remain on Runtime port 9899; port 8787 is not an acceptance entry point.
- Do not modify or depend on `bibit-security-plugin`.
- Complete one RED/GREEN cycle and commit each independently testable point before starting the next.

---

### Task 1: Security `allow_all` policy semantics

**Files:**
- Modify: `impl/bianbu-securityd/securityd/network_policy.py`
- Modify: `impl/bianbu-securityd/securityd/capability_registry.py`
- Modify: `impl/bianbu-securityd/securityd/engine.py`
- Modify: `impl/bianbu-securityd/client/runtime_launcher.py`
- Test: `impl/bianbu-securityd/tests/unit/test_network_policy.py`
- Test: `impl/bianbu-securityd/tests/unit/test_capability_registry.py`
- Test: `impl/bianbu-securityd/tests/unit/test_runtime_launcher.py`

**Interfaces:**
- Produces: `systemd_ip_filter_properties(domains: list[str], mode: str) -> list[str]`.
- Produces: verified transition from blocking properties to an empty property set.
- Preserves: existing rollback of registry version and unit properties.

- [ ] **Step 1: Write failing policy and registry tests**

```python
def test_allow_all_compiles_to_no_systemd_filter():
    assert network_policy.systemd_ip_filter_properties([], mode="allow_all") == []

def test_registry_accepts_allow_all_and_increments_version(registry):
    result = registry.set_network_policy("agent.demo", [], "allow_all")
    assert result["mode"] == "allow_all"
    assert result["version"] == 1
```

- [ ] **Step 2: Run tests and verify RED because `allow_all` is rejected or compiled as deny-all**

Run: `/tmp/bnsec-test/bin/python -m pytest -q tests/unit/test_network_policy.py tests/unit/test_capability_registry.py`

- [ ] **Step 3: Implement four-mode validation and mode-aware property compilation**

```python
VALID_MODES = frozenset({"whitelist", "deny_all", "allow_all", "learning"})

def systemd_ip_filter_properties(domains, *, mode="whitelist", dns_servers=None):
    if mode in {"allow_all", "learning"}:
        return []
    if mode == "deny_all":
        return ["IPAddressDeny=any"]
    # Existing whitelist resolution follows.
```

- [ ] **Step 4: Add RED/GREEN tests for clearing and verifying empty systemd properties**

The test must assert that a transition from `IPAddressDeny=any` to `[]` emits explicit reset assignments, verifies empty `systemctl show` output, and restores the old values on failure.

- [ ] **Step 5: Run Security network tests and commit**

Run: `/tmp/bnsec-test/bin/python -m pytest -q tests/unit/test_network_policy.py tests/unit/test_capability_registry.py tests/unit/test_runtime_launcher.py tests/unit/test_runtime_policy.py`

Commit: `feat(security): add allow-all network mode`

### Task 2: Runtime `allow_all` startup, API, and UI semantics

**Files:**
- Modify: `bianbu_agent/security/execution_runtime.py`
- Modify: `bianbu_agent/console/web/static/js/console.js`
- Test: `tests/runtime/test_execution_runtime.py`
- Test: `tests/runtime/test_security_agent_context.py`
- Test: `tests/runtime/test_security_api.py`

**Interfaces:**
- Consumes: Security mode string `allow_all`.
- Produces: no systemd network properties and a network-enabled bwrap command.
- Produces: 9899 selector option `allow_all`.

- [ ] **Step 1: Write failing Runtime tests**

```python
def test_allow_all_does_not_add_systemd_network_properties():
    policy = runtime_policy()
    policy["network"] = {"mode": "allow_all", "domains": []}
    assert execution._network_properties(policy) == []

def test_allow_all_bwrap_keeps_network_namespace(tmp_path):
    argv = backend._argv(request, decision_with_mode("allow_all"))
    assert "--unshare-net" not in argv
```

The browser contract test must parse the UI fixture and assert the mode option exists and disables the domain textarea.

- [ ] **Step 2: Run and verify RED**

Run: `/home/duancheng/workspace/bianbu-agent/bianbu-agent-runtime/.venv/bin/python -m pytest -q tests/runtime/test_execution_runtime.py tests/runtime/test_security_agent_context.py tests/runtime/test_security_api.py`

- [ ] **Step 3: Implement Runtime and 9899 UI behavior**

```javascript
<option value="allow_all">允许全部网络</option>
```

Use one mode-change handler to disable the domains textarea unless mode is `whitelist`.

- [ ] **Step 4: Run Runtime tests and commit**

Commit: `feat(runtime): add allow-all network mode`

### Task 3: Security learning event store and authenticated API

**Files:**
- Create: `impl/bianbu-securityd/securityd/network_learning.py`
- Modify: `impl/bianbu-securityd/securityd/engine.py`
- Modify: `impl/bianbu-securityd/securityd/service.py`
- Modify: `impl/bianbu-securityd/client/bianbu_security_client.py`
- Modify: `impl/bianbu-securityd/data/io.bianbu.Security.xml`
- Test: `impl/bianbu-securityd/tests/unit/test_network_learning.py`
- Test: `impl/bianbu-securityd/tests/unit/test_service_network_learning.py`

**Interfaces:**
- Produces: `NetworkLearningStore.record()`, `query()`, `clear()`, `report_status()`, and `status()`.
- Produces: `RecordNetworkLearningEvent`, `ReportNetworkLearningCollector`, `GetNetworkLearningEvents`, `GetNetworkLearningStatus`, and `ClearNetworkLearningEvents` D-Bus/client methods.
- Consumes: existing `RuntimeLeaseEngine.authorize_worker()` identity proof.

- [ ] **Step 1: Write failing real-SQLite store tests**

Cover literal DNS, IPv4, IPv6 and failed-connect fixtures; duplicate event IDs; aggregation; order; pagination; 7-day expiry; 5000-row cap; clear; malformed fields.

```python
event = {
    "event_id": "evt-1", "observed_at": 1000.0,
    "event_type": "connect", "protocol": "tcp",
    "remote_ip": "203.0.113.8", "remote_port": 443,
    "outcome": "success", "errno": "", "backend": "strace",
    "policy_version": 4,
}
assert store.record(identity, event) is True
```

- [ ] **Step 2: Run and verify RED due to the missing module**

Run: `/tmp/bnsec-test/bin/python -m pytest -q tests/unit/test_network_learning.py`

- [ ] **Step 3: Implement store, validation, aggregation, retention, and status**

Use parameterized SQLite statements and transactions. Normalize domains with the existing network policy rules and IPs with `ipaddress.ip_address`.

- [ ] **Step 4: Write failing engine/service/client contract tests**

Assert live lease succeeds, mismatched cgroup fails, non-learning mode fails, invalid collector state fails, complex query data round-trips through the client, and clear requires admin authorization.

- [ ] **Step 5: Implement D-Bus, XML and client methods, then run tests**

Run: `/tmp/bnsec-test/bin/python -m pytest -q tests/unit/test_network_learning.py tests/unit/test_service_network_learning.py tests/unit/test_network_policy.py tests/unit/test_runtime_lease.py`

- [ ] **Step 6: Commit**

Commit: `feat(security): store and query network learning events`

### Task 4: Runtime learning collector and event forwarding

**Files:**
- Create: `bianbu_agent/security/network_learning_collector.py`
- Create: `scripts/network-learning-collector.py`
- Modify: `bianbu_agent/security/execution_runtime.py`
- Modify: `bianbu_agent/security/security_runtime.py`
- Modify: `debian/rules`
- Test: `tests/runtime/test_network_learning_collector.py`
- Test: `tests/runtime/test_execution_runtime.py`
- Test: `tests/runtime/test_security_runtime.py`

**Interfaces:**
- Consumes: line-delimited JSON from the packaged script.
- Produces: `record_network_learning_event(...)` and `report_network_learning_collector(...)` calls using coordinator-owned identity.
- Produces: collector lifecycle bound to learning Worker lifecycle.

- [ ] **Step 1: Write failing parser tests with hand-checked strace fixtures**

Fixtures cover IPv4 `connect`, IPv6 `connect`, refused connection, UDP DNS QNAME/QTYPE, malformed/truncated lines, and non-DNS UDP. Expected values are literal JSON dictionaries.

- [ ] **Step 2: Run and verify RED because collector modules do not exist**

Run: `/home/duancheng/workspace/bianbu-agent/bianbu-agent-runtime/.venv/bin/python -m pytest -q tests/runtime/test_network_learning_collector.py`

- [ ] **Step 3: Implement parser and process wrapper**

The script tails only the supplied per-instance trace directory. It emits destination metadata and never accepts identity fields from trace text.

- [ ] **Step 4: Write failing coordinator tests**

Assert learning adds network syscalls to the strace expression, starts one collector after CommitStart, forwards with immutable handle/lease identity, reports active/degraded/inactive, and stops on revoke. Assert other modes do none of these.

- [ ] **Step 5: Implement coordinator/client lifecycle and package script**

Use a separate `_network_collectors` map so syscall enforcement/audit behavior cannot be weakened by learning failures.

- [ ] **Step 6: Run Runtime tests and commit**

Run: `/home/duancheng/workspace/bianbu-agent/bianbu-agent-runtime/.venv/bin/python -m pytest -q tests/runtime/test_network_learning_collector.py tests/runtime/test_execution_runtime.py tests/runtime/test_security_runtime.py`

Commit: `feat(runtime): capture learning network targets`

### Task 5: Runtime 9899 learning query and page

**Files:**
- Modify: `bianbu_agent/api/security.py`
- Modify: `bianbu_agent/console/web/static/js/console.js`
- Modify: `bianbu_agent/console/web/static/css/console.css`
- Test: `tests/runtime/test_security_api.py`
- Test: `tests/runtime/test_security_agent_context.py`

**Interfaces:**
- Produces: `network-learning.events.v1`, `network-learning.status.v1`, and `network-learning.clear.v1` through `/security-api/invoke`.
- Consumes: aggregated Security results and collector status.

- [ ] **Step 1: Write failing API tests**

Assert exact parameters, returned event fields, bounded limit/cursor, clear result, and unavailable/incompatible envelopes.

- [ ] **Step 2: Run and verify RED**

Run: `/home/duancheng/workspace/bianbu-agent/bianbu-agent-runtime/.venv/bin/python -m pytest -q tests/runtime/test_security_api.py`

- [ ] **Step 3: Implement API operation mapping**

Reject invalid pagination before calling Security. Preserve its status and event field names without fabricating empty success.

- [ ] **Step 4: Write failing page contract tests, then implement UI**

The tests must verify all four options, active/degraded/inactive branches, event columns, refresh, clear confirmation, and the distinction between no observations and degraded collection.

- [ ] **Step 5: Run Runtime UI/API tests and commit**

Commit: `feat(runtime): show network learning targets`

### Task 6: Packaging, regression, documentation, and K3 acceptance

**Files:**
- Modify: Runtime `debian/changelog`, `debian/rules`, `debian/tests/validate-source-package.sh`
- Modify: Security `debian/changelog` if its package version must advance
- Modify: `docs/review/Config-Center-Network-Policy-Completion-Review-2026-09-06.md`

**Interfaces:**
- Produces: installable riscv64 packages with monotonic Runtime manifest version.
- Produces: current acceptance evidence and manual reproduction steps.

- [ ] **Step 1: Run focused and full relevant regressions**

Security:

```bash
/tmp/bnsec-test/bin/python -m pytest -q \
  tests/unit/test_network_policy.py tests/unit/test_capability_registry.py \
  tests/unit/test_runtime_launcher.py tests/unit/test_runtime_policy.py \
  tests/unit/test_runtime_lease.py tests/unit/test_network_learning.py \
  tests/unit/test_service_network_learning.py tests/integration/test_runtime_systemd.py
```

Runtime:

```bash
/home/duancheng/workspace/bianbu-agent/bianbu-agent-runtime/.venv/bin/python -m pytest -q \
  tests/runtime/test_execution_runtime.py tests/runtime/test_security_runtime.py \
  tests/runtime/test_security_api.py tests/runtime/test_security_agent_context.py \
  tests/runtime/test_network_learning_collector.py
./debian/tests/validate-source-package.sh
```

- [ ] **Step 2: Advance package versions and run package contract tests**

Runtime manifest version must exceed the currently installed `1.2.13`; use the next monotonic version and matching Debian revision. Build Security first, then Runtime on K3.

- [ ] **Step 3: Commit packaging and acceptance documentation**

Commit each repository separately with its own package/test changes.

- [ ] **Step 4: Sync sources to `10.0.90.243`, build and install both debs**

Preserve existing machine data and unrelated services. Verify package versions, three required services, 9899 health, and Security connectivity after installation.

- [ ] **Step 5: Execute every K3 acceptance item from the spec**

Use a unique test Agent. Capture API responses, systemd properties, Worker-internal network outcomes, learning event queries, collector degraded behavior, clear/repopulate behavior, and the 9899 rendered page.

- [ ] **Step 6: Run final diff/status/commit audit**

Both worktrees must be clean, every testable point must have its own commit, and no `bibit-security-plugin` path may appear in the diffs.

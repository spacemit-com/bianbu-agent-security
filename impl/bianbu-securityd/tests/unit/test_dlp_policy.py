"""DLP-02 — 策略存储与四级回退。"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from securityd.dlp.pii_scanner import PIIType  # noqa: E402
from securityd.dlp.policy_store import (  # noqa: E402
    WILDCARD,
    DLPAction,
    DLPPolicyStore,
)


@pytest.fixture
def store(tmp_path):
    s = DLPPolicyStore(db_path=tmp_path / "dlp.db")
    yield s
    s.close()


# ———————————————————————————— 兜底策略 ————————————————————————————
def test_fallback_defaults_to_mask(store):
    """未显式配置的类型统一走 DEFAULT_ACTION=mask，不再按风险级分档。"""
    from securityd.dlp.policy_store import DEFAULT_ACTION
    assert DEFAULT_ACTION == DLPAction.MASK
    for t in PIIType:
        assert store.get_action("a", t) == DLPAction.MASK


# ———————————————————————————— 四级回退 ————————————————————————————
def test_exact_match_wins(store):
    store.set_policy("agent-a", WILDCARD, DLPAction.MASK)
    store.set_policy("agent-a", PIIType.PHONE, DLPAction.DENY)
    assert store.get_action("agent-a", PIIType.PHONE) == DLPAction.DENY
    assert store.get_action("agent-a", PIIType.EMAIL) == DLPAction.MASK


def test_agent_default_over_global(store):
    store.set_policy(WILDCARD, PIIType.PHONE, DLPAction.ALLOW)
    store.set_policy("agent-a", WILDCARD, DLPAction.DENY)
    assert store.get_action("agent-a", PIIType.PHONE) == DLPAction.DENY
    assert store.get_action("agent-b", PIIType.PHONE) == DLPAction.ALLOW


def test_global_type_policy(store):
    store.set_policy(WILDCARD, PIIType.ID_CARD, DLPAction.DENY)
    assert store.get_action("any-agent", PIIType.ID_CARD) == DLPAction.DENY


def test_global_wildcard_lowest(store):
    store.set_policy(WILDCARD, WILDCARD, DLPAction.DENY)
    assert store.get_action("x", PIIType.NAME) == DLPAction.DENY


def test_full_precedence_chain(store):
    """四级同时存在时取最精确的。"""
    store.set_policy(WILDCARD, WILDCARD, DLPAction.ALLOW)
    store.set_policy(WILDCARD, PIIType.PHONE, DLPAction.ALLOW)
    store.set_policy("agent-a", WILDCARD, DLPAction.MASK)
    store.set_policy("agent-a", PIIType.PHONE, DLPAction.DENY)
    assert store.get_action("agent-a", PIIType.PHONE) == DLPAction.DENY
    assert store.get_action("agent-a", PIIType.EMAIL) == DLPAction.MASK
    assert store.get_action("agent-b", PIIType.PHONE) == DLPAction.ALLOW
    assert store.get_action("agent-b", PIIType.EMAIL) == DLPAction.ALLOW


# ———————————————————————————— 写入 ————————————————————————————
def test_upsert_overwrites(store):
    store.set_policy("a", PIIType.PHONE, DLPAction.MASK)
    store.set_policy("a", PIIType.PHONE, DLPAction.DENY)
    assert store.get_action("a", PIIType.PHONE) == DLPAction.DENY
    assert len(store.list_policies("a")) == 1  # 不产生重复行


def test_invalid_action_rejected(store):
    with pytest.raises(ValueError, match="非法 action"):
        store.set_policy("a", PIIType.PHONE, "obliterate")


def test_accepts_string_type_and_action(store):
    store.set_policy("a", "phone", "deny")
    assert store.get_action("a", PIIType.PHONE) == DLPAction.DENY


# ———————————————————————————— manifest 导入 ————————————————————————————
def test_set_from_manifest(store):
    n = store.set_from_manifest("agent-a", {
        "default": "mask", "id_card": "deny", "name": "allow"})
    assert n == 3
    assert store.get_action("agent-a", PIIType.ID_CARD) == DLPAction.DENY
    assert store.get_action("agent-a", PIIType.NAME) == DLPAction.ALLOW
    assert store.get_action("agent-a", PIIType.EMAIL) == DLPAction.MASK  # default


def test_manifest_unknown_type_skipped(store):
    """manifest 里拼错的类型名跳过，不拖垮启动。"""
    n = store.set_from_manifest("a", {"phonee": "deny", "phone": "deny"})
    assert n == 1
    assert store.get_action("a", PIIType.PHONE) == DLPAction.DENY


def test_manifest_invalid_action_skipped(store):
    n = store.set_from_manifest("a", {"phone": "nonsense", "email": "mask"})
    assert n == 1
    assert store.get_action("a", PIIType.EMAIL) == DLPAction.MASK


def test_manifest_empty(store):
    assert store.set_from_manifest("a", {}) == 0
    assert store.set_from_manifest("a", None) == 0


def test_manifest_star_alias(store):
    """default 与 * 等价。"""
    store.set_from_manifest("a", {"*": "deny"})
    assert store.get_action("a", PIIType.NAME) == DLPAction.DENY


# ———————————————————————————— 查询 ————————————————————————————
def test_effective_matrix_covers_all_types(store):
    m = store.effective_matrix("a")
    assert set(m) == {t.value for t in PIIType}
    assert m["id_card"] == "mask"       # 兜底
    assert m["name"] == "mask"          # 兜底不分风险级


def test_enabled_types_excludes_allow(store):
    """action=allow 的类型可跳过扫描，省开销。"""
    store.set_policy("a", PIIType.NAME, DLPAction.ALLOW)
    types = store.enabled_types("a")
    assert PIIType.NAME not in types
    assert PIIType.ID_CARD in types
    assert len(types) == len(PIIType) - 1


def test_list_policies_filtered(store):
    store.set_policy("a", PIIType.PHONE, DLPAction.DENY)
    store.set_policy("b", PIIType.EMAIL, DLPAction.MASK)
    assert len(store.list_policies("a")) == 1
    assert len(store.list_policies()) == 2


def test_delete_policy(store):
    store.set_policy("a", PIIType.PHONE, DLPAction.DENY)
    assert store.delete_policy("a", PIIType.PHONE) == 1
    assert store.get_action("a", PIIType.PHONE) == DLPAction.MASK  # 回兜底


def test_delete_all_for_agent(store):
    store.set_policy("a", PIIType.PHONE, DLPAction.DENY)
    store.set_policy("a", PIIType.EMAIL, DLPAction.DENY)
    assert store.delete_policy("a") == 2
    assert store.list_policies("a") == []


def test_persistence_across_instances(tmp_path):
    """策略落库，重开实例仍在。"""
    p = tmp_path / "persist.db"
    s1 = DLPPolicyStore(db_path=p)
    s1.set_policy("a", PIIType.PHONE, DLPAction.DENY)
    s1.close()
    s2 = DLPPolicyStore(db_path=p)
    assert s2.get_action("a", PIIType.PHONE) == DLPAction.DENY
    s2.close()


@pytest.mark.skipif(not Path('/proc/self/fd').exists(), reason='Linux FD regression')
@pytest.mark.parametrize('temporary_store', [False, True])
def test_requests_release_database_fds_without_gc(tmp_path, temporary_store):
    """短命请求线程/临时 store 不得依赖 GC 才释放 SQLite 文件。"""
    import gc
    import os
    import sqlite3
    from concurrent.futures import ThreadPoolExecutor

    path = tmp_path / 'bounded.db'
    shared = DLPPolicyStore(path)

    def database_fds():
        count = 0
        for fd in Path('/proc/self/fd').iterdir():
            try:
                count += os.readlink(fd).startswith(str(path))
            except FileNotFoundError:
                pass
        return count

    def request(i):
        policy = DLPPolicyStore(path) if temporary_store else shared
        agent = f'agent-{i}'
        policy.set_policy(agent, PIIType.PHONE, DLPAction.DENY)
        assert policy.get_action(agent, PIIType.PHONE) == DLPAction.DENY
        assert len(policy.list_policies(agent)) == 1
        assert policy.delete_policy(agent) == 1
        with pytest.raises(sqlite3.IntegrityError):
            policy.set_policy(None, PIIType.PHONE, DLPAction.DENY)

    was_enabled = gc.isenabled()
    gc.disable()
    try:
        baseline = database_fds()
        for batch in range(8):
            with ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(request, range(batch * 8, (batch + 1) * 8)))
        assert database_fds() <= baseline, 'DLP connections survive completed requests'
    finally:
        shared.close()
        if was_enabled:
            gc.enable()
        gc.collect()

"""pytest 公共 fixtures（TST-01）。使用 unittest 亦可独立运行。"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

# 允许 tests/ 直接 import securityd 包
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402


@pytest.fixture()
def sec_root(monkeypatch):
    """隔离的可写根目录，重置 config 模块路径。"""
    d = tempfile.mkdtemp(prefix="bnsec_test_")
    monkeypatch.setenv("BIANBU_SEC_ROOT", d)
    # 重新加载 config 使新环境变量生效
    import importlib
    import securityd.config as cfg
    importlib.reload(cfg)
    # 依赖 config 的模块也需 reload
    for mod in ["securityd.capability_registry", "securityd.audit_chain",
                "securityd.token_meter", "securityd.key_vault",
                "securityd.seccomp_builder", "securityd.network_policy",
                "securityd.sandbox", "securityd.engine"]:
        if mod in sys.modules:
            importlib.reload(sys.modules[mod])
    yield Path(d)
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture()
def engine(sec_root):
    from securityd.engine import SecurityEngine
    eng = SecurityEngine()
    yield eng
    eng.close()


@pytest.fixture(scope="session")
def fixtures_dir():
    from tests.fixtures import make_fixtures
    make_fixtures.main()
    return Path(make_fixtures.HERE)

"""性能门禁必须使用沙箱内可见的目标解释器。"""
from pathlib import Path


def _module():
    import importlib.util

    path = Path(__file__).resolve().parents[1] / "integration/performance_benchmark.py"
    spec = importlib.util.spec_from_file_location("bnsec_performance_benchmark", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_sandbox_python_defaults_to_system_interpreter(monkeypatch):
    module = _module()
    monkeypatch.delenv("BIANBU_PERF_SANDBOX_PYTHON", raising=False)
    expected = "/usr/bin/python3" if Path("/usr/bin/python3").is_file() else module.sys.executable
    assert module._sandbox_python() == expected


def test_sandbox_python_allows_explicit_target_override(monkeypatch):
    module = _module()
    monkeypatch.setenv("BIANBU_PERF_SANDBOX_PYTHON", "/opt/bianbu/python3")
    assert module._sandbox_python() == "/opt/bianbu/python3"

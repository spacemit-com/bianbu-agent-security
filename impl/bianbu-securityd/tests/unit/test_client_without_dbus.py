"""Worker UDS must work even when dbus-python cannot be imported."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from securityd.uds_server import UdsServer


@pytest.mark.parametrize("deny", [False, True])
def test_worker_permissions_use_real_uds_without_importing_dbus(tmp_path, deny):
    requests = []
    def settings(request, uid):
        requests.append(request)
        if deny:
            return {"ok": False, "error": "lease denied"}
        return {"read": ["/opt/data"], "write": [], "custom": {"keep": True}}

    socket = tmp_path / "client.sock"
    server = UdsServer(socket_path=socket)
    server.register("permissions.settings", settings)
    server.start()
    root = Path(__file__).resolve().parents[2]
    try:
        result = subprocess.run([sys.executable, "-c", '''
import sys
import os
class NoDbus:
    def find_spec(self, fullname, *args):
        if fullname == "dbus" or fullname.startswith("dbus."):
            raise AssertionError("Worker must not import dbus")
sys.meta_path.insert(0, NoDbus())
import bianbu_security_client as client
if os.environ["TEST_DENY"] == "1":
    try:
        client.get_permission_settings("com.bianbu.test")
    except RuntimeError as exc:
        assert "lease denied" in str(exc)
    else:
        raise AssertionError("denial must propagate")
else:
    assert client.get_permission_settings("com.bianbu.test")["read"] == ["/opt/data"]
assert "dbus" not in sys.modules
'''], capture_output=True, text=True, timeout=15, env={
            **os.environ, "PYTHONPATH": f"{root / 'client'}:{root}",
            "BIANBU_SEC_UDS": str(socket), "BIANBU_WORKER_MANAGED": "1",
            "BIANBU_WORKER_INSTANCE_ID": "instance-test",
            "BIANBU_WORKER_LEASE_ID": "lease-test",
            "TEST_DENY": "1" if deny else "0",
        })
        assert result.returncode == 0, result.stderr
        assert len(requests) == 1
        assert requests[0]["_worker_instance_id"] == "instance-test"
        assert requests[0]["_worker_lease_id"] == "lease-test"
    finally:
        server.stop()


def test_capability_catalog_resolves_with_only_the_client_dir_on_path():
    """只把 client 目录放进 sys.path 时也能读到权威工具目录。

    Runtime 的搜索路径只包含客户端发布目录，securityd 包是它的兄弟目录；
    客户端必须从自身位置推导出包根，否则 capability_catalog 静默返回空表，
    UI 就退回「按 Agent 已注册能力」渲染，按框架分表失效。
    """
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run([sys.executable, '-c', '''
import json
import sys
import bianbu_security_client as client
assert 'securityd' not in sys.modules
runtime = client.capability_catalog('runtime')
hermes = client.capability_catalog('hermes')
print(json.dumps({'runtime': len(runtime), 'hermes': len(hermes),
                  'frameworks': sorted({row['framework'] for row in hermes})}))
'''],
        capture_output=True, text=True, timeout=15,
        env={**os.environ, 'PYTHONPATH': str(root / 'client')},
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout.strip().splitlines()[-1])
    assert payload['runtime'] > 0
    assert payload['hermes'] > payload['runtime']
    assert payload['frameworks'] == ['hermes']

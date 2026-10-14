"""The deployed client directory works without importing daemon code."""
from pathlib import Path
import subprocess
import sys


def test_standalone_client_uses_local_digest_without_daemon_imports(tmp_path):
    client_dir = Path(__file__).resolve().parents[2] / "client"
    package = tmp_path / "skill"
    package.mkdir()
    (package / "SKILL.md").write_text("test package")
    (package / ".signature").write_text("detached-signature")
    script = '''
import importlib.abc
import sys
import types
sys.path.insert(0, sys.argv[1])
class RejectDaemon(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "securityd" or fullname.startswith("securityd."):
            raise AssertionError("client imported daemon code")
sys.meta_path.insert(0, RejectDaemon())
sys.modules["dbus"] = types.ModuleType("dbus")
import bianbu_security_client as client
from bianbu_security_codesign import describe_code_package
expected = describe_code_package(sys.argv[2])
class Proxy:
    def VerifyCodeDigest(self, digest, signature, kind, **kwargs):
        assert (digest, signature) == expected
        assert signature == "detached-signature"
        assert kind == "skill"
        return {"allowed": True, "signed": True, "valid": True}
    def VerifyCodePackage(self, *args, **kwargs):
        raise AssertionError("daemon must not read caller paths")
client._get_proxy = lambda: Proxy()
assert client.verify_code_package(sys.argv[2], "skill")["allowed"] is True
'''
    subprocess.run([sys.executable, "-I", "-c", script, str(client_dir), str(package)],
                   check=True, timeout=20, capture_output=True, text=True)

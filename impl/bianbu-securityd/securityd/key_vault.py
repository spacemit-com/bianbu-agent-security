"""Key Vault（FR-AI-21 / [TBD-17] 软件方案 / KV-01~03）。

worker K3 无 TEE → 软件方案：
- 服务级 secret：加密文件（cryptography Fernet，密钥文件 root-only 0600）
- 普通 Agent 经 CheckPermission 门控，不可直读密钥文件

对齐设计 §2.2 §11.3。gnome-keyring 用户级存储作为可选后端（此处以加密文件为默认，
可跨 headless 场景，keyring 后端在有会话总线时启用）。
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from . import config
from .errors import NotFound


class KeyVault:
    def __init__(self, keys_dir: Path | None = None):
        self.keys_dir = Path(keys_dir) if keys_dir else config.KEYS_DIR
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.keys_dir.chmod(0o700)
        except PermissionError:
            pass
        self._master = self._load_or_create_master()

    def _load_or_create_master(self) -> bytes:
        mk = self.keys_dir / "master.key"
        if mk.exists():
            return mk.read_bytes()
        # 生成 32 字节主密钥
        import os
        key = os.urandom(32)
        mk.write_bytes(key)
        try:
            mk.chmod(0o600)
        except PermissionError:
            pass
        return key

    def _fernet(self):
        from cryptography.fernet import Fernet
        # 由 master 派生 Fernet key（32B urlsafe base64）
        derived = hashlib.sha256(self._master).digest()
        return Fernet(base64.urlsafe_b64encode(derived))

    def _store_path(self, agent_id: str) -> Path:
        safe = agent_id.replace("/", "_")
        return self.keys_dir / f"{safe}.vault"

    def put_secret(self, agent_id: str, key: str, value: str) -> bool:
        """写入 agent 命名空间下的 secret（加密落盘）。"""
        f = self._fernet()
        path = self._store_path(agent_id)
        store = {}
        if path.exists():
            store = json.loads(f.decrypt(path.read_bytes()).decode("utf-8"))
        store[key] = value
        path.write_bytes(f.encrypt(json.dumps(store).encode("utf-8")))
        try:
            path.chmod(0o600)
        except PermissionError:
            pass
        return True

    def get_secret(self, agent_id: str, key: str) -> str:
        """读取 secret（调用方须已通过 CheckPermission 门控）。"""
        path = self._store_path(agent_id)
        if not path.exists():
            raise NotFound(f"agent {agent_id} 无密钥库")
        f = self._fernet()
        store = json.loads(f.decrypt(path.read_bytes()).decode("utf-8"))
        if key not in store:
            raise NotFound(f"密钥 {key} 不存在")
        return store[key]

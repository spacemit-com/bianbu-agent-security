"""Security-integrated Agent Runtime reference service.

该服务是 Runtime/agent 侧的生命周期与 Security 绑定实现。它不请求
securityd 的 Pause/Stop/Terminate；每次执行开始时用自身 D-Bus sender 建立
Security caller 绑定，使后续判权有可信主体。
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import threading
import time
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

from client.runtime_identity import RuntimeSecurityIdentity


INTERFACE = "io.bianbu.Runtime"
OBJECT_PATH = "/io/bianbu/Runtime"
BUS_NAME = "io.bianbu.Runtime"
STATES = {"INSTALLED", "RUNNING", "PAUSED", "STOPPED", "TERMINATED"}
TRANSITIONS = {
    "INSTALLED": {"RUNNING"},
    "RUNNING": {"PAUSED", "STOPPED", "TERMINATED"},
    "PAUSED": {"RUNNING", "STOPPED", "TERMINATED"},
    "STOPPED": {"RUNNING", "TERMINATED"},
    "TERMINATED": set(),
}


@dataclass
class AgentRecord:
    agent_id: str
    name: str
    state: str = "INSTALLED"
    session_id: str = ""
    run_id: str = ""
    started_at: float = 0.0
    checkpoint_count: int = 0
    reason: str = ""
    # 由 Runtime 自身在 Register 时提供被管理 Agent 的主 PID；Securityd
    # 不猜测或伪造该身份。未提供时资源接口明确返回 resource_available=false。
    pid: int = 0


class RuntimeService(dbus.service.Object):
    def __init__(self, bus: dbus.Bus, state_dir: str | Path):
        super().__init__(bus, OBJECT_PATH)
        self.bus = bus
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.records_path = self.state_dir / "agents.json"
        self.checkpoints_dir = self.state_dir / "checkpoints"
        self.checkpoints_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._records: dict[str, AgentRecord] = self._load_records()
        self._identities: dict[str, RuntimeSecurityIdentity] = {}
        self._messages: list[dict[str, str]] = []
        self._last_proc_samples: dict[str, tuple[float, float]] = {}
        self._restore_running_identities()

    def _restore_running_identities(self) -> None:
        """Runtime 重启后恢复持久化状态并重建 Security 身份绑定。"""
        for rec in self._records.values():
            if rec.state not in {"RUNNING", "PAUSED"}:
                continue
            if not (rec.session_id and rec.run_id):
                rec.state = "STOPPED"
                rec.reason = "missing runtime context after restart"
                continue
            try:
                self._identity(rec).bind_security_identity(self.bus)
            except Exception as exc:  # noqa: BLE001
                # 无法重新建立 Security 绑定时，拒绝继续运行，避免无门禁执行。
                rec.state = "STOPPED"
                rec.reason = f"security restore failed: {exc}"
        self._save_records()

    def _load_records(self) -> dict[str, AgentRecord]:
        try:
            raw = json.loads(self.records_path.read_text())
            return {k: AgentRecord(**{f: v[f] for f in AgentRecord.__dataclass_fields__ if f in v})
                    for k, v in raw.items()}
        except (OSError, ValueError, TypeError):
            return {}

    def _save_records(self) -> None:
        tmp = self.records_path.with_suffix(".tmp")
        tmp.write_text(json.dumps({k: asdict(v) for k, v in self._records.items()},
                                  ensure_ascii=False, indent=2) + "\n")
        os.replace(tmp, self.records_path)

    def _record(self, agent_id: str) -> AgentRecord:
        try:
            return self._records[str(agent_id)]
        except KeyError as exc:
            raise ValueError(f"agent not found: {agent_id}") from exc

    def _transition(self, rec: AgentRecord, target: str, reason: str = "") -> str:
        if target not in STATES or target not in TRANSITIONS[rec.state]:
            raise ValueError(f"invalid transition {rec.state}->{target}")
        old = rec.state
        rec.state = target
        rec.reason = reason
        self._save_records()
        self.StateChanged(rec.agent_id, old, target)
        return target

    def _identity(self, rec: AgentRecord) -> RuntimeSecurityIdentity:
        identity = self._identities.get(rec.agent_id)
        if identity is None:
            identity = RuntimeSecurityIdentity(
                agent_id=rec.agent_id, session_id=rec.session_id,
                run_id=rec.run_id)
            self._identities[rec.agent_id] = identity
        return identity

    @dbus.service.signal(INTERFACE, signature="sss")
    def StateChanged(self, agent_id: str, old: str, new: str):
        pass

    @dbus.service.signal(INTERFACE, signature="ssx")
    def ResourceExceeded(self, agent_id: str, resource: str, value: int):
        pass

    @dbus.service.method(INTERFACE, in_signature="ssa{sv}", out_signature="b")
    def Register(self, agent_id: str, name: str, metadata: dict) -> bool:
        aid = str(agent_id)
        with self._lock:
            if aid in self._records:
                return False
            meta = {str(k): v for k, v in dict(metadata).items()}
            try:
                pid = int(meta.get("pid", 0) or 0)
            except (TypeError, ValueError):
                raise ValueError("metadata.pid must be an integer")
            if pid < 0:
                raise ValueError("metadata.pid must be >= 0")
            self._records[aid] = AgentRecord(aid, str(name), pid=pid)
            self._save_records()
            return True

    @dbus.service.method(INTERFACE, in_signature="s", out_signature="s")
    def Start(self, agent_id: str) -> str:
        with self._lock:
            rec = self._record(agent_id)
            if rec.state not in {"INSTALLED", "STOPPED"}:
                raise ValueError(f"cannot start from {rec.state}")
            # STOPPED→RUNNING 是新一次运行；不能沿用上一 run 的
            # session/run 约束，否则旧事件可能错误影响新执行上下文。
            old_identity = self._identities.pop(rec.agent_id, None)
            if old_identity is not None:
                old_identity.close()
            rec.session_id = uuid.uuid4().hex
            rec.run_id = uuid.uuid4().hex
            rec.started_at = time.time()
            rec.reason = ""
            # BindAgentV2 使用本 Runtime 进程的真实 D-Bus sender。
            self._identity(rec).bind_security_identity(self.bus)
            self._transition(rec, "RUNNING")
            return "RUNNING"

    @dbus.service.method(INTERFACE, in_signature="sb", out_signature="s")
    def Pause(self, agent_id: str, snapshot: bool) -> str:
        with self._lock:
            rec = self._record(agent_id)
            if snapshot:
                self._checkpoint(rec)
            return self._transition(rec, "PAUSED", "requested")

    @dbus.service.method(INTERFACE, in_signature="s", out_signature="s")
    def Resume(self, agent_id: str) -> str:
        with self._lock:
            rec = self._record(agent_id)
            return self._transition(rec, "RUNNING", "resumed")

    @dbus.service.method(INTERFACE, in_signature="s", out_signature="s")
    def Stop(self, agent_id: str) -> str:
        with self._lock:
            rec = self._record(agent_id)
            self._checkpoint(rec)
            return self._transition(rec, "STOPPED", "requested")

    @dbus.service.method(INTERFACE, in_signature="s", out_signature="s")
    def Terminate(self, agent_id: str) -> str:
        with self._lock:
            rec = self._record(agent_id)
            return self._transition(rec, "TERMINATED", "requested")

    def _checkpoint(self, rec: AgentRecord) -> str:
        rec.checkpoint_count += 1
        ckpt = f"ckpt-{rec.checkpoint_count}-{uuid.uuid4().hex[:8]}"
        d = self.checkpoints_dir / rec.agent_id
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{ckpt}.json").write_text(json.dumps({
            "checkpoint_id": ckpt, "agent_id": rec.agent_id,
            "state": rec.state, "session_id": rec.session_id,
            "run_id": rec.run_id, "created_at": time.time()}, indent=2) + "\n")
        self._save_records()
        return ckpt

    @dbus.service.method(INTERFACE, in_signature="s", out_signature="s")
    def Checkpoint(self, agent_id: str) -> str:
        with self._lock:
            return self._checkpoint(self._record(agent_id))

    @dbus.service.method(INTERFACE, in_signature="ss", out_signature="s")
    def Restore(self, agent_id: str, checkpoint_id: str) -> str:
        with self._lock:
            rec = self._record(agent_id)
            if rec.state == "TERMINATED":
                raise ValueError("terminated runtime cannot be restored")
            path = self.checkpoints_dir / rec.agent_id / f"{checkpoint_id}.json"
            if not path.is_file() or path.is_symlink():
                raise ValueError("checkpoint not found")
            try:
                snap = json.loads(path.read_text())
            except (OSError, ValueError) as exc:
                raise ValueError("checkpoint is unreadable") from exc
            if str(snap.get("agent_id")) != rec.agent_id:
                raise ValueError("checkpoint agent mismatch")
            target = str(snap.get("state", ""))
            if target not in {"RUNNING", "PAUSED", "STOPPED"}:
                raise ValueError("checkpoint has invalid state")
            old = rec.state
            old_identity = self._identities.pop(rec.agent_id, None)
            if old_identity is not None:
                old_identity.close()
            rec.session_id = str(snap.get("session_id", ""))
            rec.run_id = str(snap.get("run_id", ""))
            if not rec.session_id or not rec.run_id:
                raise ValueError("checkpoint missing runtime context")
            rec.state = target
            rec.reason = "restored"
            if target in {"RUNNING", "PAUSED"}:
                try:
                    self._identity(rec).bind_security_identity(self.bus)
                except Exception as exc:  # noqa: BLE001
                    rec.state = "STOPPED"
                    rec.reason = f"security restore failed: {exc}"
                    self._save_records()
                    raise ValueError(rec.reason) from exc
            self._save_records()
            if old != rec.state:
                self.StateChanged(rec.agent_id, old, rec.state)
            return "RESTORED"

    @dbus.service.method(INTERFACE, in_signature="s", out_signature="aa{sv}")
    def ListCheckpoints(self, agent_id: str):
        rec = self._record(agent_id)
        d = self.checkpoints_dir / rec.agent_id
        rows = []
        for p in sorted(d.glob("*.json")):
            try:
                x = json.loads(p.read_text())
                rows.append(dbus.Dictionary({k: dbus.String(str(v)) for k, v in x.items()},
                                             signature="sv"))
            except (OSError, ValueError):
                continue
        return rows

    @dbus.service.method(INTERFACE, in_signature="s", out_signature="a{sv}")
    def GetResourceStats(self, agent_id: str):
        rec = self._record(agent_id)
        stats = self._sample_resource(rec)
        return dbus.Dictionary({k: (dbus.Double(v) if isinstance(v, float)
                                    else dbus.Boolean(v) if isinstance(v, bool)
                                    else dbus.Int64(int(v)) if isinstance(v, int)
                                    else dbus.String(str(v)))
                                for k, v in stats.items()}, signature="sv")

    @staticmethod
    def _proc_stats(pid: int) -> tuple[float, int] | None:
        """读取 Runtime 提供的 Agent PID；读取失败绝不伪造资源值。"""
        if pid <= 0:
            return None
        try:
            stat = Path(f"/proc/{pid}/stat").read_text()
            # comm 可含空格/括号，取最后一个 ')' 后的字段更稳健。
            fields = stat.rsplit(")", 1)[1].split()
            utime, stime = int(fields[11]), int(fields[12])
            rss_pages = int(fields[21])
            page = os.sysconf("SC_PAGESIZE")
            hz = os.sysconf("SC_CLK_TCK")
            cpu = (utime + stime) / max(1, hz)
            return cpu, rss_pages * page
        except (OSError, ValueError, IndexError):
            return None

    def _sample_resource(self, rec: AgentRecord) -> dict[str, Any]:
        now = time.time()
        uptime = max(0, int(now - rec.started_at)) if rec.started_at else 0
        sample = {"state": rec.state, "cpu_pct": 0.0, "mem_rss": 0,
                  "uptime_s": uptime, "pid": rec.pid,
                  "resource_available": False, "sampled_at": now}
        values = self._proc_stats(rec.pid)
        if values is not None:
            cpu_seconds, rss = values
            sample["cpu_seconds"] = round(cpu_seconds, 3)
            sample["mem_rss"] = rss
            sample["resource_available"] = True
            previous = self._last_proc_samples.get(rec.agent_id)
            if previous is not None:
                old_cpu, old_ts = previous
                elapsed = now - old_ts
                if elapsed > 0:
                    sample["cpu_pct"] = round(max(0.0, (cpu_seconds - old_cpu) /
                                                   elapsed * 100.0), 2)
            self._last_proc_samples[rec.agent_id] = (cpu_seconds, now)
        history = self.state_dir / f"resource-{rec.agent_id}.jsonl"
        with history.open("a", encoding="utf-8") as f:
            f.write(json.dumps(sample, ensure_ascii=False) + "\n")
        return sample

    @dbus.service.method(INTERFACE, in_signature="ss", out_signature="s")
    def ExportResourceHistory(self, agent_id: str, fmt: str) -> str:
        rec = self._record(agent_id)
        self._sample_resource(rec)
        out = self.state_dir / f"resource-{agent_id}.{('csv' if fmt == 'csv' else 'json')}"
        src = self.state_dir / f"resource-{agent_id}.jsonl"
        rows = []
        if src.is_file():
            for line in src.read_text(encoding="utf-8").splitlines():
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    continue
        if fmt == "csv":
            import csv
            with out.open("w", newline="", encoding="utf-8") as f:
                fields = ["sampled_at", "state", "pid", "cpu_pct", "cpu_seconds",
                          "mem_rss", "uptime_s", "resource_available"]
                w = csv.DictWriter(f, fieldnames=fields)
                w.writeheader(); w.writerows({k: r.get(k, "") for k in fields} for r in rows)
        else:
            out.write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n",
                            encoding="utf-8")
        return str(out)

    @dbus.service.method(INTERFACE, in_signature="", out_signature="aa{sv}")
    def List(self):
        return [dbus.Dictionary({k: dbus.String(str(v)) for k, v in asdict(r).items()},
                                signature="sv") for r in self._records.values()]

    @dbus.service.method(INTERFACE, in_signature="sss", out_signature="b")
    def SendMessage(self, sender: str, target: str, payload: str) -> bool:
        self._record(sender); self._record(target)
        self._messages.append({"from": str(sender), "to": str(target), "payload": str(payload)})
        return True

    @dbus.service.method(INTERFACE, in_signature="sss", out_signature="b")
    def CanCall(self, agent_id: str, session_id: str, operation: str) -> bool:
        rec = self._record(agent_id)
        if rec.session_id != str(session_id):
            return False
        return rec.state == "RUNNING"

    def close(self) -> None:
        for identity in self._identities.values():
            identity.close()
        self._identities.clear()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--state-dir", default=os.environ.get(
        "BIANBU_RUNTIME_STATE_DIR", "/var/lib/bianbu/runtime"))
    ap.add_argument("--session", action="store_true")
    args = ap.parse_args(argv)
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus() if args.session else dbus.SystemBus()
    name = dbus.service.BusName(BUS_NAME, bus=bus, do_not_queue=True)
    service = RuntimeService(bus, args.state_dir)
    loop = GLib.MainLoop()
    def stop(*_args):
        service.close(); loop.quit()
    signal.signal(signal.SIGTERM, stop); signal.signal(signal.SIGINT, stop)
    print("bianbu-agent-runtimed ready", flush=True)
    try:
        loop.run()
    finally:
        service.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

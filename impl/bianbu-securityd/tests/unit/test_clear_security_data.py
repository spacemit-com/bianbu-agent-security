from pathlib import Path
import os
import subprocess

SCRIPT = Path(__file__).resolve().parents[2] / 'deploy/clear-security-data.sh'


def invoke(root, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith('BIANBU_')}
    return subprocess.run(['bash', str(SCRIPT), '--root', str(root), *args],
                          capture_output=True, text=True, env=env, timeout=20)


def seed(root):
    files = ['etc/bianbu/capabilities.db', 'etc/bianbu/capabilities.db-wal',
             'etc/bianbu/capabilities.db-shm',
             'etc/bianbu/dlp_policy.db', 'etc/bianbu/runtime-leases.db',
             'etc/bianbu/syscall_policy.db', 'etc/bianbu/keys/master.key',
             'etc/bianbu/keys/agent.vault', 'etc/bianbu/security-agent-prune-old/plan.json',
             'var/log/bianbu/audit/network-learning.db', 'var/log/bianbu/audit/syscall-events.db',
             'var/log/bianbu/audit/audit.db-journal', 'var/log/bianbu/security-clear-backups/old.db',
             'run/bianbu/sandbox/agent/seccomp.bpf', 'run/bianbu/securityd.sock',
             'run/bianbu/syscall-audit/worker.json', 'run/bianbu/network-learning/collector.sock',
             'run/bianbu-syscall-audit/events.jsonl', 'run/bianbu-syscall-audit/events.jsonl.1',
             'var/lib/bianbu/agents/agent/data', 'var/lib/bianbu/runtime/agents.json']
    keep = ['etc/bianbu/codesign-keys/vendor.pub', 'etc/bianbu/webui.env',
            'run/bianbu/agent-memoryd.sock', 'var/log/bianbu/unrelated.log',
            'usr/lib/bianbu-securityd/program.py']
    for name in files + keep:
        p = root / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text('sentinel')
    return [root / p for p in files], [root / p for p in keep]


def test_default_preview_does_not_mutate(tmp_path):
    erased, kept = seed(tmp_path)
    result = invoke(tmp_path)
    assert result.returncode == 0, result.stderr
    assert all(p.read_text() == 'sentinel' for p in erased + kept)
    assert 'runtime-leases.db' in result.stdout


def test_reset_removes_owned_state_preserves_install_and_directory_metadata(tmp_path):
    erased, kept = seed(tmp_path)
    dirs = [tmp_path / p for p in ['etc/bianbu', 'etc/bianbu/keys', 'var/log/bianbu/audit',
                                     'run/bianbu/network-learning', 'var/lib/bianbu/agents']]
    for p in dirs: p.chmod(0o750)
    before = [(p.stat().st_ino, p.stat().st_mode, p.stat().st_uid, p.stat().st_gid) for p in dirs]
    result = invoke(tmp_path, '--yes')
    assert result.returncode == 0, result.stderr
    assert not any(p.exists() for p in erased)
    assert all(p.read_text() == 'sentinel' for p in kept)
    assert before == [(p.stat().st_ino, p.stat().st_mode, p.stat().st_uid, p.stat().st_gid) for p in dirs]
    assert invoke(tmp_path, '--yes').returncode == 0


def test_symlink_escape_refuses_before_any_deletion(tmp_path):
    root = tmp_path / 'root'; erased, _ = seed(root)
    victim = tmp_path / 'outside'; victim.mkdir(); (victim/'keep').write_text('keep')
    (root/'etc/bianbu/keys/agent.vault').unlink()
    (root/'etc/bianbu/keys/master.key').unlink()
    (root/'etc/bianbu/keys').rmdir(); (root/'etc/bianbu/keys').symlink_to(victim)
    result = invoke(root, '--yes')
    assert result.returncode != 0
    assert erased[0].exists() and (victim/'keep').read_text() == 'keep'


def test_nested_symlink_is_unlinked_without_following_target(tmp_path):
    root=tmp_path/'root'; seed(root)
    outside=tmp_path/'outside'; outside.mkdir(); (outside/'data').write_text('keep')
    (root/'var/log/bianbu/audit/link').symlink_to(outside)
    result=invoke(root,'--yes')
    assert result.returncode == 0,result.stderr
    assert (outside/'data').read_text()=='keep'
    assert not (root/'var/log/bianbu/audit/link').exists()


def test_dry_run_overrides_yes(tmp_path):
    erased,_=seed(tmp_path)
    result=invoke(tmp_path,'--yes','--dry-run')
    assert result.returncode==0,result.stderr
    assert all(p.exists() for p in erased)


def test_refuses_filesystem_root():
    assert invoke(Path('/'),'--yes').returncode != 0


def test_engine_can_initialize_again_with_fresh_registry_key_and_audit(tmp_path):
    env = dict(os.environ, BIANBU_SEC_ROOT=str(tmp_path),
               BIANBU_AGENTS_HOME=str(tmp_path/'var/lib/bianbu/agents'))
    source = SCRIPT.parents[1]
    code = '''
from securityd.engine import SecurityEngine
from securityd import config
engine = SecurityEngine()
assert engine.registry.list_agents() == []
engine.register_agent('com.bianbu.resettest', {'name': 'reset test'})
assert len(engine.registry.list_agents()) == 1
assert engine.audit.verify_live()
assert (config.KEYS_DIR / 'master.key').stat().st_size == 32
'''
    import sys
    first = subprocess.run([sys.executable, '-c', code], cwd=source, env=env, capture_output=True, text=True)
    assert first.returncode == 0, first.stderr
    old_key = (tmp_path/'etc/bianbu/keys/master.key').read_bytes()
    result = invoke(tmp_path, '--yes')
    assert result.returncode == 0, result.stderr
    second = subprocess.run([sys.executable, '-c', code], cwd=source, env=env, capture_output=True, text=True)
    assert second.returncode == 0, second.stderr
    assert (tmp_path/'etc/bianbu/keys/master.key').read_bytes() != old_key


def load_helper():
    import importlib.util
    spec = importlib.util.spec_from_file_location('clear_security_data', SCRIPT.with_suffix('.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_stop_failure_preserves_data_and_restores_masks(tmp_path, monkeypatch):
    helper = load_helper()
    erased, _ = seed(tmp_path)
    calls = []
    def fail_stop(self):
        calls.append('stop')
        raise RuntimeError('service did not stop')
    monkeypatch.setattr(helper.Services, 'stop', fail_stop)
    monkeypatch.setattr(helper.Services, 'restore', lambda self: calls.append('restore'))
    assert helper.main(['--root', str(tmp_path), '--yes']) == 1
    assert calls == ['stop', 'restore']
    assert all(p.exists() for p in erased)


def test_explicit_root_refuses_agent_data_outside_root(tmp_path, monkeypatch):
    helper = load_helper()
    erased, _ = seed(tmp_path/'root')
    monkeypatch.setenv('BIANBU_AGENTS_HOME', str(tmp_path/'outside'))
    assert helper.main(['--root', str(tmp_path/'root'), '--yes']) == 1
    assert all(p.exists() for p in erased)


def test_ineffective_mask_aborts_before_stop_and_is_restored(monkeypatch, tmp_path):
    helper = load_helper()
    plan = helper.Plan(tmp_path)
    plan.isolated = False
    calls = []
    def fake(args):
        calls.append(args)
        if 'list-units' in args:
            return 'bianbu-securityd.service loaded active running daemon\n'
        if 'show' in args:
            return 'loaded\n'
        return ''
    monkeypatch.setattr(helper, 'command', fake)
    services = helper.Services(plan)
    def refuse_fallback(unit):
        raise RuntimeError('mask and condition unavailable')
    monkeypatch.setattr(services, 'block_local_unit', refuse_fallback)
    import pytest
    with pytest.raises(RuntimeError, match='mask'):
        services.stop()
    services.restore()
    assert not any('stop' in args for args in calls)
    assert any('unmask' in args for args in calls)


def test_live_daemon_with_trailing_slash_root_is_stopped(tmp_path):
    import sys
    import time
    module_root = tmp_path/'modules'
    package = module_root/'securityd'
    package.mkdir(parents=True)
    (package/'__init__.py').write_text('')
    (package/'service.py').write_text('import time\nfrom pathlib import Path\nPath("ready").touch()\ntime.sleep(60)\n')
    root = tmp_path/'state'
    seed(root)
    env = dict(os.environ, BIANBU_SEC_ROOT=str(root)+'/',
               BIANBU_AGENTS_HOME=str(root/'var/lib/bianbu/agents'))
    proc = subprocess.Popen([sys.executable, '-m', 'securityd.service'], cwd=module_root, env=env)
    try:
        for _ in range(100):
            if (module_root/'ready').exists():
                break
            time.sleep(.02)
        assert (module_root/'ready').exists()
        result = invoke(root, '--yes')
        assert result.returncode == 0, result.stderr
        assert proc.wait(timeout=2) != 0
    finally:
        if proc.poll() is None:
            proc.terminate()
        proc.wait(timeout=5)


def test_legacy_nft_cleanup_only_removes_owned_table(tmp_path, monkeypatch):
    import json
    helper = load_helper()
    plan = helper.Plan(tmp_path)
    plan.isolated = False
    marker = plan.run/'sandbox/agent/enforcement.json'
    marker.parent.mkdir(parents=True)
    marker.write_text(json.dumps({'backend': 'nft'}))
    calls = []
    def fake(args):
        calls.append(args)
        if 'list' in args:
            return json.dumps({'nftables': [{'table': {'family': 'inet', 'name': 'bianbu_security'}},
                                          {'table': {'family': 'inet', 'name': 'other'}}]})
        return ''
    monkeypatch.setattr(helper, 'command', fake)
    helper.check_legacy_kernel(plan)
    assert calls[-1] == ['nft', 'delete', 'table', 'inet', 'bianbu_security']
    assert len(calls) == 2


def test_transient_worker_stopped_after_launchers_and_late_worker_rechecked(tmp_path, monkeypatch):
    helper = load_helper()
    plan = helper.Plan(tmp_path)
    plan.isolated = False
    plan.system = True
    core = 'bianbu-securityd.service'
    worker = 'bianbu-agent-test-123456789abc.service'
    late = 'bianbu-agent-test-abcdef123456.scope'
    calls = []
    masked = set()
    lists = []
    def fake(args):
        calls.append(args)
        if 'list-units' in args:
            lists.append(1)
            units = [core, worker] if len(lists) == 1 else [core, worker, late]
            return '\n'.join(unit+' loaded active running' for unit in units)
        if 'show' in args:
            unit = args[args.index('show')+1]
            if '--property=FragmentPath' in args:
                return '/run/systemd/transient/'+unit if unit == worker else '/lib/systemd/system/'+unit
            if '--property=LoadState' in args:
                return 'masked' if unit in masked else 'loaded'
            if '--property=ActiveState' in args:
                return 'inactive'
        if 'mask' in args:
            masked.add(args[-1])
        return ''
    monkeypatch.setattr(helper, 'command', fake)
    services = helper.Services(plan)
    services.stop()
    services.restore()
    assert masked == {core}
    assert any('stop' in args and worker in args for args in calls)
    assert any('stop' in args and late in args for args in calls)


def test_local_unit_uses_guard_condition_and_restores_files(tmp_path, monkeypatch):
    helper = load_helper()
    plan = helper.Plan(tmp_path)
    plan.system = True
    services = helper.Services(plan)
    calls = []
    # Redirect only this module's /run Path to a disposable runtime tree.
    real_path = helper.Path
    monkeypatch.setattr(helper, 'Path', lambda value: tmp_path/'run' if str(value) == '/run' else real_path(value))
    (tmp_path/'run').mkdir()
    def fake(args):
        calls.append(args)
        if 'get-property' in args:
            import json
            return json.dumps({'data': [['ConditionPathExists', False, True, services.guard.name+'/block', 0]]})
        return ''
    monkeypatch.setattr(helper, 'command', fake)
    services.block_local_unit('bianbu-security-webui.service')
    guard = real_path(services.guard.name)
    dropin = services.dropins[0]
    assert guard.exists() and 'ConditionPathExists=!' in dropin.read_text()
    services.restore()
    assert not guard.exists() and not dropin.exists()
    assert sum('daemon-reload' in args for args in calls) == 2


def test_runtime_home_prompt_defaults_to_keep_and_warns(tmp_path, monkeypatch, capsys):
    helper = load_helper()
    profile = tmp_path/'home/alice/.bianbu-agent'
    profile.mkdir(parents=True)
    (profile/'config.yaml').write_text('config')
    monkeypatch.setattr(helper.sys.stdin, 'isatty', lambda: True)
    prompts = []
    monkeypatch.setattr('builtins.input', lambda prompt: prompts.append(prompt) or '')
    assert helper.confirm_runtime_profiles([profile]) == []
    assert (profile/'config.yaml').exists()
    assert '聊天历史' in capsys.readouterr().out
    assert str(profile) in prompts[0]


def test_runtime_home_delete_requires_explicit_yes(tmp_path, monkeypatch):
    helper = load_helper()
    profile = tmp_path/'home/alice/.bianbu-agent'
    profile.mkdir(parents=True)
    (profile/'history.db').write_text('history')
    keep = profile.parent/'unrelated'; keep.write_text('keep')
    monkeypatch.setattr(helper.sys.stdin, 'isatty', lambda: True)
    monkeypatch.setattr('builtins.input', lambda _: 'yes')
    plan = helper.Plan(tmp_path)
    plan.runtime_profiles = helper.confirm_runtime_profiles([profile])
    plan.erase()
    assert not profile.exists()
    assert keep.read_text() == 'keep'


def test_noninteractive_runtime_home_is_kept(tmp_path, monkeypatch):
    helper = load_helper()
    profile = tmp_path/'.bianbu-agent'; profile.mkdir()
    monkeypatch.setattr(helper.sys.stdin, 'isatty', lambda: False)
    monkeypatch.setattr('builtins.input', lambda _: __import__('pytest').fail('must not prompt'))
    assert helper.confirm_runtime_profiles([profile]) == []


def test_selected_runtime_home_symlink_refuses_before_security_deletion(tmp_path):
    import pytest
    helper = load_helper()
    erased, _ = seed(tmp_path/'root')
    outside = tmp_path/'outside'; outside.mkdir()
    profile = tmp_path/'root/home/alice/.bianbu-agent'
    profile.parent.mkdir(parents=True); profile.symlink_to(outside)
    plan = helper.Plan(tmp_path/'root'); plan.runtime_profiles = [profile]
    with pytest.raises(ValueError, match='符号链接'):
        plan.erase()
    assert all(p.exists() for p in erased)


def test_runtime_user_discovery_uses_service_accounts_not_root_home(tmp_path, monkeypatch):
    from types import SimpleNamespace
    import pwd
    helper = load_helper()
    plan = SimpleNamespace(isolated=False, system=True)
    alice = tmp_path/'alice'; (alice/'.bianbu-agent').mkdir(parents=True)
    monkeypatch.setattr(helper, 'command', lambda _: 'bianbu-agent-runtime@alice.service loaded active running\n')
    monkeypatch.setattr(pwd, 'getpwnam', lambda user: SimpleNamespace(pw_dir=str(alice), pw_uid=1000) if user=='alice' else (_ for _ in ()).throw(KeyError(user)))
    monkeypatch.setenv('HOME', '/root')
    assert helper.runtime_profiles(plan) == [alice/'.bianbu-agent']


def test_runtime_profile_preserved_when_services_fail_to_stop(tmp_path, monkeypatch):
    helper = load_helper()
    root = tmp_path/'root'; erased, _ = seed(root)
    profile = root/'home/alice/.bianbu-agent'
    profile.mkdir(parents=True); (profile/'chat.db').write_text('history')
    monkeypatch.setattr(helper, 'runtime_profiles', lambda plan: [profile])
    monkeypatch.setattr(helper, 'confirm_runtime_profiles', lambda profiles: profiles)
    def fail_stop(self):
        raise RuntimeError('stop failed')
    monkeypatch.setattr(helper.Services, 'stop', fail_stop)
    assert helper.main(['--root', str(root), '--yes']) == 1
    assert (profile/'chat.db').read_text() == 'history'
    assert all(p.exists() for p in erased)


def test_preview_never_prompts_or_deletes_runtime_profile(tmp_path, monkeypatch):
    helper = load_helper()
    profile = tmp_path/'home/alice/.bianbu-agent'; profile.mkdir(parents=True)
    monkeypatch.setattr(helper, 'runtime_profiles', lambda plan: [profile])
    monkeypatch.setattr(helper, 'confirm_runtime_profiles', lambda _: __import__('pytest').fail('preview must not ask'))
    assert helper.main(['--root', str(tmp_path), '--yes', '--dry-run']) == 0
    assert profile.exists()


def test_terminal_confirmation_deletes_only_selected_profile(tmp_path):
    import pty
    import select
    import sys
    import time
    root = tmp_path/'state'; seed(root)
    profile = root/'home/alice/.bianbu-agent'; profile.mkdir(parents=True)
    (profile/'chat.db').write_text('history')
    harness = tmp_path/'run_reset.py'
    harness.write_text('''import importlib.util, pathlib, sys
spec=importlib.util.spec_from_file_location('reset',sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
root=pathlib.Path(sys.argv[2])
module.runtime_profiles=lambda plan:[root/'home/alice/.bianbu-agent']
sys.exit(module.main(['--root',str(root),'--yes']))
''')
    master, slave = pty.openpty()
    proc = subprocess.Popen([sys.executable, str(harness), str(SCRIPT.with_suffix('.py')), str(root)],
                            stdin=slave, stdout=slave, stderr=slave)
    os.close(slave)
    transcript = b''
    try:
        end = time.monotonic()+10
        while '直接回车保留'.encode() not in transcript:
            assert time.monotonic() < end, transcript.decode(errors='replace')
            if select.select([master], [], [], .2)[0]:
                transcript += os.read(master, 65536)
        os.write(master, b'yes\n')
        result = proc.wait(timeout=10)
        try:
            while select.select([master], [], [], .1)[0]:
                transcript += os.read(master, 65536)
        except OSError:
            pass
        assert result == 0, transcript.decode(errors='replace')
        assert '聊天历史'.encode() in transcript
        assert not profile.exists()
        assert (root/'etc/bianbu/codesign-keys/vendor.pub').exists()
    finally:
        if proc.poll() is None:
            proc.terminate(); proc.wait(timeout=5)
        os.close(master)

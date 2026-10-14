#!/usr/bin/env python3
"""Reset Security-owned persistent and volatile state; never import the daemon."""
import argparse
import fnmatch
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys

DATABASES = ('capabilities.db', 'dlp_policy.db',
             'runtime-leases.db', 'syscall_policy.db')
UNITS = ('bianbu-securityd.service', 'bianbu-security-webui.service',
         'bianbu-agent-network-learning.service', 'bianbu-syscall-observer.service',
         'bianbu-agent-runtimed.service', 'bibit-security-adapter.service',
         'bianbu-agent-runtime.service', 'bianbu-agent-runtime@*.service', 'bibit-runtime-adapter@*.service',
         'bianbu-agent-*-????????????.scope', 'bianbu-agent-*-????????????.service', 'bianbu-security-dev-*.service')


def safe_path(path):
    path = Path(os.path.abspath(path))
    if path in [Path(p) for p in ('/', '/etc', '/var', '/run', '/usr', '/tmp', '/home', '/root')] or path == Path.home():
        raise ValueError(f'拒绝危险路径: {path}')
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError(f'拒绝符号链接路径: {part}')
    return path


class Plan:
    def __init__(self, root=None):
        self.runtime_profiles = []
        self.isolated = bool(root)
        self.system = not root and os.geteuid() == 0
        self.root = safe_path(root) if root else None
        base = self.root or (Path('/') if self.system else Path(os.environ.get('XDG_DATA_HOME', str(Path.home()/'.local/share')))/'bianbu-securityd')
        def configured(env, default):
            return base/default if root else Path(os.environ.get(env, str(base/default)))
        etc = configured('BIANBU_ETC', 'etc/bianbu')
        run = configured('BIANBU_RUN', 'run/bianbu')
        log = configured('BIANBU_LOG', 'var/log/bianbu')
        self.etc, self.run, self.log = etc, run, log
        agents = Path(os.environ.get('BIANBU_AGENTS_HOME', str(base/'var/lib/bianbu/agents' if root or self.system else Path.home()/'.local/share/bianbu-agents')))
        self.agents = agents
        self.dirs = [etc/'keys', log/'audit', log/'security-clear-backups', run/'sandbox',
                     run/'syscall-audit', run/'network-learning', agents]
        self.files = [etc/(db+suffix) for db in DATABASES for suffix in ('', '-wal', '-shm', '-journal')]
        self.files += [Path(os.environ.get('BIANBU_SEC_UDS', str(run/'securityd.sock'))), run/'agent-network-learning.sock']
        self.backups = sorted(etc.glob('security-agent-prune-*'))
        self.dirs += self.backups
        if root or self.system:
            self.dirs += [base/'run/bianbu-syscall-audit', base/'var/lib/bianbu/runtime']
        if not root:
            dev = Path(os.environ.get('XDG_RUNTIME_DIR', '/tmp'))/'bianbu-security-dev'
            logs = Path(os.environ.get('SECD_LOG_DIR', '/var/tmp/bnsec-logs'))
            self.files += [dev/name for name in ('webui.pid', 'webui.log', 'securityd.pid', 'securityd.log')]
            self.files += [logs/name for name in ('securityd.log', 'sec-webui.log', '_run_securityd.sh', '_run_secwebui.sh')]
            for directory, names in ((dev, ('webui.log', 'securityd.log')), (logs, ('securityd.log', 'sec-webui.log'))):
                for name in names:
                    self.files += sorted(directory.glob(name+'.*'))
        self.validate()

    def validate(self):
        for path in [self.etc, self.run, self.log, *self.dirs, *self.files, *self.runtime_profiles]:
            safe_path(path)
            if self.root and not path.is_relative_to(self.root):
                raise ValueError(f'路径不在 --root 内: {path}')
        for profile in self.runtime_profiles:
            if profile.name != ".bianbu-agent" or profile.is_mount():
                raise ValueError(f"拒绝不安全的 Runtime 用户目录: {profile}")
        for path in [*self.dirs, *self.runtime_profiles]:
            if path.exists() and not path.is_dir():
                raise ValueError(f'预期目录: {path}')
            for current, dirs, _ in os.walk(path, followlinks=False):
                for name in dirs:
                    child = Path(current)/name
                    if not child.is_symlink() and child.is_mount():
                        raise ValueError(f'清理目录内存在挂载点，请先卸载: {child}')
        for path in self.files:
            if path.is_dir():
                raise ValueError(f'预期文件: {path}')

    def erase(self):
        self.validate()
        for directory in self.dirs:
            if directory.exists():
                for child in directory.iterdir():
                    if child.is_dir() and not child.is_symlink():
                        shutil.rmtree(child)
                    else:
                        child.unlink()
        for path in self.files:
            path.unlink(missing_ok=True)
        for path in self.backups:
            if path.exists():
                path.rmdir()
        for profile in self.runtime_profiles:
            if profile.exists():
                shutil.rmtree(profile)


def command(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=45)
    if result.returncode:
        raise RuntimeError(f'{args!r}: {result.stderr.strip()}')
    return result.stdout


class Services:
    def __init__(self, plan):
        self.plan = plan
        self.masked = []
        self.units = []
        self.dropins = []
        self.created_dirs = []
        self.guard = None
        self.ctl = ['systemctl'] + ([] if plan.system else ['--user'])

    def stop(self):
        if self.plan.isolated:
            return
        if not self.plan.system and not (Path('/run/user')/str(os.geteuid())/'systemd/private').exists():
            return
        output = command(self.ctl + ['list-units', '--all', '--plain', '--no-legend', *UNITS])
        self.units = [line.split()[0] for line in output.splitlines() if line.split() and any(fnmatch.fnmatch(line.split()[0], p) for p in UNITS)]
        # Include inactive installed activation targets, not just loaded units.
        installed = command(self.ctl + ['list-unit-files', '--no-legend', *UNITS])
        self.units = sorted(set(self.units + [line.split()[0] for line in installed.splitlines() if line.split() and '@.' not in line.split()[0] and any(fnmatch.fnmatch(line.split()[0], p) for p in UNITS)]))
        for unit in self.units:
            fragment = command(self.ctl + ['show', unit, '--property=FragmentPath', '--value']).strip()
            if unit.endswith('.scope') or fragment.startswith('/run/systemd/transient/') or '/systemd/transient/' in fragment:
                # Transient units outrank runtime masks; stopping their parent
                # launchers and then stopping the units prevents recreation.
                continue
            state = command(self.ctl + ['show', unit, '--property=LoadState', '--value']).strip()
            if state != 'masked':
                command(self.ctl + ['mask', '--runtime', unit])
                self.masked.append(unit)
                effective = command(self.ctl + ['show', unit, '--property=LoadState', '--value']).strip()
                if effective != 'masked':
                    self.block_local_unit(unit)
        if self.units:
            command(self.ctl + ['stop', *self.units])
            # A worker could have been created while its Runtime was stopping.
            output = command(self.ctl + ['list-units', '--all', '--plain', '--no-legend', *UNITS])
            remaining = [line.split()[0] for line in output.splitlines() if line.split() and any(fnmatch.fnmatch(line.split()[0], p) for p in UNITS)]
            if remaining:
                command(self.ctl + ['stop', *remaining])
            for unit in sorted(set(self.units + remaining)):
                state = command(self.ctl + ['show', unit, '--property=ActiveState', '--value']).strip()
                if state not in ('inactive', 'failed'):
                    raise RuntimeError(f'服务未停止: {unit}: {state}')

    def block_local_unit(self, unit):
        import tempfile
        runtime = Path('/run') if self.plan.system else Path('/run/user')/str(os.geteuid())
        if self.guard is None:
            self.guard = tempfile.TemporaryDirectory(prefix='bianbu-security-reset-', dir=runtime)
            (Path(self.guard.name)/'block').touch()
        base = runtime/'systemd/system' if self.plan.system else runtime/'systemd/user'
        directory = base/(unit+'.d')
        if not directory.exists():
            directory.mkdir(parents=True)
            self.created_dirs.append(directory)
        path = directory/('zz-'+Path(self.guard.name).name+'.conf')
        self.dropins.append(path)
        path.write_text('[Unit]\nConditionPathExists=!'+self.guard.name+'/block\n')
        command(self.ctl + ['daemon-reload'])
        import json
        encoded = ''.join(chr(ch) if chr(ch).isascii() and chr(ch).isalnum() else f'_{ch:02x}' for ch in unit.encode())
        bus = ['busctl'] + ([] if self.plan.system else ['--user'])
        conditions = json.loads(command(bus + ['--json=short', 'get-property',
            'org.freedesktop.systemd1', '/org/freedesktop/systemd1/unit/'+encoded,
            'org.freedesktop.systemd1.Unit', 'Conditions']))
        if not any(row[:4] == ['ConditionPathExists', False, True, self.guard.name+'/block']
                   for row in conditions.get('data', [])):
            raise RuntimeError(f'临时启动条件未生效: {unit}；未删除数据')

    def restore(self):
        try:
            if self.masked:
                command(self.ctl + ['unmask', '--runtime', *self.masked])
        finally:
            for path in self.dropins:
                path.unlink(missing_ok=True)
            for directory in self.created_dirs:
                directory.rmdir()
            if self.guard is not None:
                self.guard.cleanup()
            if self.dropins:
                command(self.ctl + ['daemon-reload'])


def stop_standalone(plan):
    """Stop matching daemons by PID identity; unrelated data roots are untouched."""
    modules = ('securityd.service', 'webui.production', 'webui.app', 'runtime.runtime_service')
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid():
            continue
        try:
            if os.geteuid() != 0 and proc.stat().st_uid != os.geteuid():
                continue
            args = (proc/'cmdline').read_bytes().split(b'\0')
            matches = any(args[i:i+2] == [b'-m', m.encode()] for i in range(len(args)-1) for m in modules)
            if not matches:
                continue
            identity = (proc/'stat').read_text().rsplit(')', 1)[1].split()[19]
            env = dict(item.split(b'=', 1) for item in (proc/'environ').read_bytes().split(b'\0') if b'=' in item)
            if plan.isolated:
                raw_root = env.get(b'BIANBU_SEC_ROOT')
                if not raw_root:
                    continue
                process_root = Path(os.fsdecode(raw_root))
                if not process_root.is_absolute():
                    process_root = (proc/'cwd').resolve()/process_root
                if process_root.resolve() != plan.root:
                    continue
                raw_agents = env.get(b'BIANBU_AGENTS_HOME')
                if not raw_agents or Path(os.fsdecode(raw_agents)).resolve() != plan.agents.resolve():
                    raise RuntimeError(f'进程 {proc.name} 的 BIANBU_AGENTS_HOME 与隔离清理目录不一致；未删除数据')
            elif env.get(b'BIANBU_SEC_ROOT'):
                continue
            else:
                raise RuntimeError(f'仍有非托管 Security 进程 {proc.name}；请先停止其启动器再清理')
            fd = os.pidfd_open(int(proc.name))
            try:
                if (proc/'stat').read_text().rsplit(')', 1)[1].split()[19] != identity:
                    raise ProcessLookupError('PID reused')
                signal.pidfd_send_signal(fd, signal.SIGTERM)
                import select
                poll = select.poll(); poll.register(fd, select.POLLIN)
                if not poll.poll(10000):
                    raise RuntimeError(f'进程 {proc.name} 未退出，未清理数据')
            finally:
                os.close(fd)
        except (FileNotFoundError, ProcessLookupError):
            continue


def check_legacy_kernel(plan):
    if plan.isolated:
        return
    import json
    import time
    sandbox = plan.run/'sandbox'
    markers = [json.loads(marker.read_text()) for marker in sandbox.glob('*/enforcement.json')]
    # Old iptables mode used unlabelled shared OUTPUT rules. Do not flush a
    # host firewall, or destroy the only evidence needed to undo those rules.
    if any(data.get('backend') == 'iptables' for data in markers):
        raise RuntimeError('发现旧式 iptables 全局规则；请先撤销对应规则，保留 enforcement.json 供核对')
    if any(data.get('backend') == 'nft' for data in markers):
        tables = json.loads(command(['nft', '-j', 'list', 'tables']))
        if any(item.get('table', {}).get('name') == 'bianbu_security' and
               item.get('table', {}).get('family') == 'inet' for item in tables.get('nftables', [])):
            command(['nft', 'delete', 'table', 'inet', 'bianbu_security'])
    cgbase = Path(os.environ.get('BIANBU_SECURITY_CGROUP_PARENT',
                  os.environ.get('BIANBU_SECURITY_CGROUP_ROOT', '/sys/fs/cgroup')))
    if cgbase != cgbase.resolve() or not cgbase.is_relative_to('/sys/fs/cgroup'):
        raise ValueError(f'不安全的 cgroup 根: {cgbase}')
    if sandbox.exists():
        for agent in sandbox.iterdir():
            safe_id = ''.join(ch if ch.isalnum() or ch in '._-' else '_' for ch in agent.name)
            cg = cgbase/f'bianbu-{safe_id}'
            if not cg.exists():
                continue
            safe_path(cg)
            if 'populated 1' in (cg/'cgroup.events').read_text():
                (cg/'cgroup.kill').write_text('1')
                for _ in range(100):
                    if 'populated 1' not in (cg/'cgroup.events').read_text():
                        break
                    time.sleep(.05)
                else:
                    raise RuntimeError(f'沙箱未退出: {cg}')
            # cgroup control files are virtual; rmdir is the kernel API.
            for child in sorted((p for p in cg.rglob('*') if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
                child.rmdir()
            cg.rmdir()


def runtime_profiles(plan):
    """Resolve Runtime service users through passwd, never sudo's HOME."""
    import pwd
    import re
    if plan.isolated:
        return []
    users = set()
    if plan.system:
        output = command(['systemctl', 'list-units', '--all', '--plain', '--no-legend',
                          'bianbu-agent-runtime@*.service'])
        for line in output.splitlines():
            match = re.fullmatch(r'bianbu-agent-runtime@([A-Za-z_][A-Za-z0-9_.-]*)\.service',
                                 line.split()[0]) if line.split() else None
            if match:
                users.add(match.group(1))
        marker = Path('/var/lib/bianbu-agent-runtime/desktop-user')
        if marker.is_file():
            users.add(marker.read_text().strip())
        if not users and os.environ.get('SUDO_USER') not in (None, '', 'root'):
            users.add(os.environ['SUDO_USER'])
    else:
        users.add(pwd.getpwuid(os.geteuid()).pw_name)
    profiles = set()
    for user in sorted(users):
        try:
            account = pwd.getpwnam(user)
        except KeyError:
            continue
        profile = Path(account.pw_dir)/'.bianbu-agent'
        if profile.exists() or profile.is_symlink():
            profiles.add(profile)
    return sorted(profiles)


def confirm_runtime_profiles(profiles):
    selected = []
    for profile in profiles:
        print(f'可选删除 Runtime 用户目录: {profile}')
        print('删除该目录会清除 Bianbu Agent Runtime 的所有用户配置信息、Agent 数据和聊天历史，无法恢复。')
        if not sys.stdin.isatty():
            print('非交互执行：保留该目录。--yes 不代表同意删除 Runtime 用户数据。')
            continue
        try:
            answer = input(f'是否删除 {profile}？输入 yes 确认，直接回车保留: ')
        except EOFError:
            answer = ''
        if answer.strip().lower() == 'yes':
            selected.append(profile)
        else:
            print(f'保留: {profile}')
    return selected


def ensure_runtime_stopped(plan):
    if plan.isolated or not plan.runtime_profiles:
        return
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid():
            continue
        try:
            if os.geteuid() != 0 and proc.stat().st_uid != os.geteuid():
                continue
            args = [os.fsdecode(arg) for arg in (proc/'cmdline').read_bytes().split(b'\0') if arg]
            if any(Path(arg).name in ('bianbu-agent-runtime', 'bianbu-agent') or
                   arg == 'bianbu_agent' or arg.startswith('bianbu_agent.') for arg in args):
                raise RuntimeError(f'Runtime 进程 {proc.name} 仍在运行，请先停止其启动器；未删除数据')
        except (FileNotFoundError, ProcessLookupError):
            continue


def main(argv=None):
    parser = argparse.ArgumentParser(description='重置 Security 运行数据（默认只预览；保留安装文件、信任公钥和服务配置）')
    parser.add_argument('--root', default=os.environ.get('BIANBU_SEC_ROOT'), help='隔离数据根；不操作主机 systemd 或内核状态')
    parser.add_argument('--yes', action='store_true', help='确认永久删除；不自动备份')
    parser.add_argument('--dry-run', action='store_true', help='只预览，优先于 --yes')
    parser.add_argument('--no-backup', action='store_true', help='兼容旧调用；重置默认不备份')
    args = parser.parse_args(argv)
    try:
        plan = Plan(args.root)
        for path in plan.dirs:
            print(f'清空目录（保留权限）: {path}')
        for path in plan.files:
            print(f'删除文件: {path}')
        if not args.yes or args.dry_run:
            for profile in runtime_profiles(plan):
                print(f'可选删除（执行时另行确认，默认保留）: {profile}；包含所有用户配置和聊天历史')
            print('预览：未停止服务、未删除数据。使用 --yes 执行。')
            return 0
        plan.runtime_profiles = confirm_runtime_profiles(runtime_profiles(plan))
        plan.validate()
        services = Services(plan)
        def interrupted(signum, frame):
            raise RuntimeError(f'收到信号 {signum}，停止清理')
        previous_term = signal.signal(signal.SIGTERM, interrupted)
        try:
            services.stop()
            stop_standalone(plan)
            ensure_runtime_stopped(plan)
            check_legacy_kernel(plan)
            plan.erase()
        finally:
            try:
                services.restore()
            finally:
                signal.signal(signal.SIGTERM, previous_term)
        for profile in plan.runtime_profiles:
            print(f'已删除 Runtime 用户目录: {profile}')
        print('Security 自有运行数据已重置；服务保持停止，可正常重新启动。')
        print('保留：安装/配置/信任公钥、系统共享 journal、其他应用日志和外部备份。')
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f'清理失败: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())

import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location('kernel_probe', Path(__file__).parent/'scripts/kernel_probe.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def test_fixture_emits_only_fixed_invalid_fd_probe_then_stops():
    message, finish = probe.completion([{'role': 'user', 'content': 'arbitrary command'}])
    assert finish == 'tool_calls'
    tool = message['tool_calls'][0]['function']
    assert tool['name'] == 'terminal'
    assert json.loads(tool['arguments']) == {'command': probe.COMMAND}
    assert 'syscall(273,-1,0,0)' in probe.COMMAND
    message, finish = probe.completion([{'role': 'tool', 'content': '{}'}])
    assert finish == 'stop' and 'tool_calls' not in message

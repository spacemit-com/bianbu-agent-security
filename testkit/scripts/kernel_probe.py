#!/usr/bin/env python3
"""Deterministic K3 acceptance: local model -> terminal -> seccomp -> kernel audit.

Run on the Worker, with Runtime and securityd already running. The only syscall
probe uses fd=-1, so it cannot load a kernel module. No cloud model is involved.
"""
import argparse
import errno
import json
import os
from pathlib import Path
import platform
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.request
import uuid

COMMAND = "python3 -c 'import ctypes,json,os; c=ctypes.CDLL(None,use_errno=True); r=c.syscall(273,-1,0,0); print(json.dumps(dict(probe=\"BNSEC_INVALID_FD\",ret=r,errno=ctypes.get_errno(),pid=os.getpid())))'"


def completion(messages):
    if any(item.get('role') == 'tool' for item in messages):
        return {'role': 'assistant', 'content': 'Kernel probe finished.'}, 'stop'
    return {'role': 'assistant', 'content': None, 'tool_calls': [
        {'id': 'call_kernel_probe', 'type': 'function', 'function': {
            'name': 'terminal', 'arguments': json.dumps({'command': COMMAND})}}]}, 'tool_calls'


class ModelHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        message, finish = completion(body.get('messages', []))
        result = {'id': 'kernel-probe', 'object': 'chat.completion', 'created': int(time.time()),
                  'model': 'kernel-probe', 'choices': [{'index': 0, 'message': message, 'finish_reason': finish}],
                  'usage': {'prompt_tokens': 1, 'completion_tokens': 1, 'total_tokens': 2}}
        if body.get('stream'):
            delta = dict(message)
            if delta.get('tool_calls'):
                delta['tool_calls'][0]['index'] = 0
            chunk = {**result, 'object': 'chat.completion.chunk',
                     'choices': [{'index': 0, 'delta': delta, 'finish_reason': None}]}
            end = {**chunk, 'choices': [{'index': 0, 'delta': {}, 'finish_reason': finish}]}
            content = ('data: '+json.dumps(chunk)+'\n\ndata: '+json.dumps(end)+'\n\ndata: [DONE]\n\n').encode()
            content_type = 'text/event-stream'
        else:
            content = json.dumps(result).encode(); content_type = 'application/json'
        self.send_response(200); self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(content))); self.end_headers(); self.wfile.write(content)

    def do_GET(self):
        content = json.dumps({'object': 'list', 'data': [{'id': 'kernel-probe', 'object': 'model'}]}).encode()
        self.send_response(200); self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(content))); self.end_headers(); self.wfile.write(content)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--keep-agent', action='store_true', help='Keep the temporary agent for UI audit inspection; remove it afterwards.')
    args = parser.parse_args()
    if platform.machine() != 'riscv64':
        parser.error('This probe requires the K3 riscv64 Worker (finit_module=273).')
    server = ThreadingHTTPServer(('127.0.0.1', 0), ModelHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    provider = 'custom:kernel-probe-'+uuid.uuid4().hex[:12]
    aid = None; provider_created = False; success = False
    evidence = {'model': 'deterministic local fixture', 'command': COMMAND}
    args.out.parent.mkdir(parents=True, exist_ok=True)

    def req(method, path, body=None):
        request = urllib.request.Request('http://127.0.0.1:9899'+path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=120) as response:
            return json.loads(response.read() or '{}')

    def sec(op, **params):
        result = req('POST', '/security-api/invoke', {'protocolVersion': 1, 'serviceId': 'security',
            'requestId': uuid.uuid4().hex, 'operationId': op, 'params': {'agent_id': aid, **params}})
        if not result['ok'] or result['result'].get('ok') is False:
            raise RuntimeError(result)
        return result['result']

    try:
        req('POST', '/api/v1/providers', {'id': provider, 'base_url': f'http://127.0.0.1:{server.server_port}/v1', 'api_key': 'local-probe'})
        provider_created = True
        base = req('GET', '/api/v1/agents')['data'][0]
        agent = req('POST', '/api/v1/agents', {'name': 'Kernel invalid-fd acceptance',
            'model': {'provider': provider, 'name': 'kernel-probe'}, 'permissions': base['permissions'],
            'tools': ['terminal'], 'skills': [], 'plugins': ['bianbu.security'], 'mcps': [],
            'metadata': {'execution': {'requested_mode': 'sandbox'}}})['data']
        aid = agent['id']; evidence.update(agent_id=aid, provider_id=provider)
        sec('network-policy.update.v1', mode='allow_all', domains=[])
        sec('agents.security-mode.update.v1', mode='yolo')
        os.environ.update(PA_AGENT_ID=aid, BIANBU_PA_AGENT_ID=aid, BIANBU_SECURITYD_HOME='/usr/lib/bianbu-securityd')
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from engine import Ctx
        evidence['run'] = Ctx().run_prompt('Execute the fixed acceptance probe.', timeout=120, approve_tools=('terminal',))
        sid = evidence['run']['session_id']
        events = req('GET', f'/api/v1/sessions/{sid}/events?max_messages=50')['data']
        evidence['events'] = events
        outputs = [e['data'] for e in events if e['type'] == 'tool/call.completed']
        assert outputs, 'No tool executed; model refusal is not a kernel verdict'
        probe = None
        for output in outputs:
            result = output.get('result', {})
            if isinstance(result, str): result = json.loads(result)
            for line in str(result.get('output', '')).splitlines():
                try: candidate = json.loads(line)
                except ValueError: continue
                if candidate.get('probe') == 'BNSEC_INVALID_FD': probe = candidate
        assert probe and probe['ret'] == -1 and probe['errno'] == errno.EPERM, outputs
        evidence['syscall_result'] = probe
        # The tool reports a PID inside its sandbox namespace; eBPF reports a
        # host PID. Correlate the fresh Agent/instance/lease, not unequal namespaces.
        deadline = time.monotonic()+10
        kernel = []
        while time.monotonic() < deadline:
            kernel = sec('syscall-audit.events.v1', limit=100, cursor=0).get('value', [])
            kernel = [row for row in kernel if row.get('worker_agent_id') == aid
                      and row.get('syscall') == 'finit_module' and row.get('backend') == 'ebpf-seccomp'
                      and str(row.get('instance_id', '')).startswith(aid+'-')
                      and row.get('lease_id') and int(row.get('pid', 0)) > 0]
            if kernel: break
            time.sleep(0.2)
        evidence['kernel_events'] = kernel
        evidence['pid_namespaces'] = 'syscall_result.pid is sandbox PID; kernel_events.pid is host PID'
        assert kernel, 'No matching new kernel audit event'
        assert all(row.get('action') == 'deny' for row in kernel), kernel
        success = True
        print(json.dumps({'agent_id': aid, 'session_id': sid, 'kernel_events': kernel}, ensure_ascii=False))
    finally:
        evidence['passed'] = success
        args.out.write_text(json.dumps(evidence, ensure_ascii=False, indent=2))
        if aid and not (success and args.keep_agent):
            req('DELETE', '/api/v1/agents/'+aid)
        if provider_created and not (success and args.keep_agent):
            req('DELETE', '/api/v1/providers/'+provider)
        server.shutdown(); server.server_close()


if __name__ == '__main__':
    main()

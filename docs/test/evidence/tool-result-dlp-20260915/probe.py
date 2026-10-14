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

COMMAND = "python3 -c 'print(" + '"138"+"2468"+"1357"' + ")'"


CAPTURES = []

def completion(messages):
    CAPTURES.append(messages)
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
    server = ThreadingHTTPServer(('127.0.0.1', 0), ModelHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    provider = 'custom:tool-dlp-'+uuid.uuid4().hex[:12]
    aid = None
    rows = []
    def req(method, path, body=None):
        request = urllib.request.Request('http://127.0.0.1:9899'+path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=120) as response:
            return json.loads(response.read() or '{}')
    def sec(op, **params):
        r=req('POST', '/security-api/invoke', dict(protocolVersion=1, serviceId='security',
            requestId=uuid.uuid4().hex, operationId=op, params=dict(agent_id=aid, **params)))
        assert r['ok'],r
        return r['result']
    try:
        req('POST','/api/v1/providers',dict(id=provider, base_url=f'http://127.0.0.1:{server.server_port}/v1',api_key='local-probe'))
        base=req('GET','/api/v1/agents')['data'][0]
        agent=req('POST','/api/v1/agents',dict(name='Tool DLP acceptance',model=dict(provider=provider,name='kernel-probe'),
            permissions=base['permissions'],tools=['terminal'],skills=[],mcps=[],plugins=['bianbu.security'],
            metadata={'execution':{'requested_mode':'sandbox'}}))['data']
        aid=agent['id']
        sec('network-policy.update.v1',mode='allow_all',domains=[])
        os.environ.update(PA_AGENT_ID=aid,BIANBU_PA_AGENT_ID=aid,BIANBU_SECURITYD_HOME='/usr/lib/bianbu-securityd')
        sys.path.insert(0,'/var/tmp/bnsec-d8a8f04c/source/testkit')
        from engine import Ctx
        for mode in ['normal','yolo']:
            sec('agents.security-mode.update.v1',mode=mode)
            for action in ['mask','block']:
                CAPTURES.clear()
                sec('dlp.policy.update.v1',pii_type='phone',action=action)
                run=Ctx().run_prompt('Run the fixed local test command.',timeout=120,approve_tools=('terminal',))
                outgoing=json.dumps(CAPTURES,ensure_ascii=False)
                assert '13824681357' not in outgoing, outgoing
                if action=='mask':
                    assert run['status']=='completed',run
                    assert 'PII' in outgoing, outgoing
                else:
                    assert run['status']=='failed',run
                    assert len(CAPTURES)==1,CAPTURES
                rows.append(dict(mode=mode,action=action,run=run,requests=list(CAPTURES)))
                print(mode,action,'PASS',flush=True)
    finally:
        Path('/var/tmp/bnsec-d8a8f04c/tool-result-dlp.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2))
        if aid: req('DELETE','/api/v1/agents/'+aid)
        req('DELETE','/api/v1/providers/'+provider)
        server.shutdown()

if __name__ == '__main__': main()

"""Isolated audit read benchmark; never opens the service's live database.

Run: python3 testkit/benchmark_audit_query.py --rows 10000 100000 1000000
Synthetic valid chains are inserted in batches; timings exclude setup/startup.
"""
import argparse
import json
from pathlib import Path
import statistics
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'impl/bianbu-securityd'))
from securityd.audit_chain import AuditChainEngine, compute_hash
from securityd import config


def benchmark(count):
    with tempfile.TemporaryDirectory(prefix='audit-query-bench-') as directory:
        engine = AuditChainEngine(Path(directory) / 'audit.db')
        previous = config.GENESIS_HASH
        for start in range(1, count + 1, 10000):
            batch = []
            for seq in range(start, min(start + 10000, count + 1)):
                ts, aid = '2026-09-20T00:00:00.000+00:00', 'bench'
                op = 'hook:before_tool' if seq % 100 == 0 else 'op'
                result = 'deny' if seq % 1000 == 0 else 'allow'
                target = 'x' * 128
                digest = compute_hash(seq, ts, aid, op, target, result, previous)
                batch.append((seq, ts, aid, op, target, result, previous, digest))
                previous = digest
            engine._conn.executemany('INSERT INTO audit_record VALUES (?,?,?,?,?,?,?,?)', batch)
            engine._conn.commit()
        for kind in ('all', 'hook', 'deny'):
            for cursor in (0, count // 2):
                query = json.dumps(dict(agent_id='bench', limit=100, filter=kind,
                                        cursor=cursor, snapshot_seq=count))
                samples = []
                for _ in range(25):
                    start = time.perf_counter()
                    page = engine.query(query)
                    samples.append((time.perf_counter() - start) * 1000)
                assert len(page['records']) <= 100
                print(json.dumps(dict(rows=count, filter=kind, cursor=cursor,
                                      returned=len(page['records']),
                                      median_ms=round(statistics.median(samples), 2),
                                      p95_ms=round(sorted(samples)[23], 2))), flush=True)
        engine.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rows', type=int, nargs='+', default=[10000, 100000])
    args = parser.parse_args()
    for count in args.rows:
        if count < 1:
            parser.error('--rows must be positive')
        benchmark(count)

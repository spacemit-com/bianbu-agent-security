#!/usr/bin/env python3
"""生成/验证发布资产 SHA-256 清单，供升级前后完整性复核。"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def _files(root: Path) -> list[Path]:
    skip = {"__pycache__", ".pytest_cache", ".git", "sbom.json"}
    return sorted(p for p in root.rglob("*") if p.is_file()
                  and not any(part in skip for part in p.relative_to(root).parts)
                  and not p.name.endswith((".pyc", ".pyo")))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=None)
    ap.add_argument("--output", default="release-manifest.json")
    ap.add_argument("--verify", default=None, help="用已有清单验证 root")
    args = ap.parse_args(argv)
    root = Path(args.root).resolve() if args.root else Path(__file__).resolve().parents[1]
    entries = []
    for p in _files(root):
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        entries.append({"path": p.relative_to(root).as_posix(), "sha256": h,
                        "size": p.stat().st_size})
    result = {"format": "bianbu-release-manifest-v1", "root": str(root),
              "files": entries}
    if args.verify:
        expected = json.loads(Path(args.verify).read_text())
        actual = {(x["path"], x["sha256"], x["size"]) for x in entries}
        wanted = {(x["path"], x["sha256"], x["size"]) for x in expected.get("files", [])}
        if actual != wanted:
            print("RELEASE_MANIFEST_FAIL changed_files=" + str(len(actual ^ wanted)))
            return 1
        print("RELEASE_MANIFEST_PASS files=" + str(len(entries)))
        return 0
    Path(args.output).write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print("RELEASE_MANIFEST_GENERATED files=" + str(len(entries)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

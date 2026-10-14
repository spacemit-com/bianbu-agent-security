#!/usr/bin/env python3
"""校验 D-Bus XML、service.py、client SDK 和生产 policy 的契约一致性。

该脚本不需要启动守护进程，适合 CI 和发布前检查。它只校验业务方法名、
XML/service 方法集合及 data/deploy policy 是否意外分叉；具体签名由 XML
introspection 和 Python 装饰器在集成测试中继续验证。
"""
from __future__ import annotations

import re
import sys
import ast
from pathlib import Path
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
XML = ROOT / "data/io.bianbu.Security.xml"
SERVICE = ROOT / "securityd/service.py"
CLIENT = ROOT / "client/bianbu_security_client.py"
DEPLOY_POLICY = ROOT / "deploy/io.bianbu.Security.conf"
DATA_POLICY = ROOT / "data/io.bianbu.Security.conf"


def _xml_methods() -> set[str]:
    root = ET.parse(XML).getroot()
    return {x.attrib["name"] for x in root.findall("./interface/method")}


def _decorated_methods() -> set[str]:
    tree = ast.parse(SERVICE.read_text())
    methods = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                if dec.func.attr == "method":
                    methods.add(node.name)
    return methods


def _client_methods() -> set[str]:
    text = CLIENT.read_text()
    return set(re.findall(r"proxy\.(\w+)\(", text))


def _policy_signature(path: Path) -> tuple:
    """忽略注释/空白，对 policy 元素做稳定语义比较。"""
    root = ET.parse(path).getroot()
    rows = []
    for node in root.iter():
        if node.tag == "policy":
            attrs = tuple(sorted(node.attrib.items()))
            rules = tuple(sorted((child.tag, tuple(sorted(child.attrib.items())))
                                 for child in node))
            rows.append((attrs, rules))
    return tuple(sorted(rows))


def main() -> int:
    xml_methods = _xml_methods()
    service_methods = _decorated_methods()
    client_methods = _client_methods() & xml_methods
    errors: list[str] = []
    if xml_methods != service_methods:
        errors.append(f"XML/service mismatch: xml-only={sorted(xml_methods-service_methods)} "
                      f"service-only={sorted(service_methods-xml_methods)}")
    if not client_methods.issubset(xml_methods):
        errors.append(f"client methods absent from XML: {sorted(client_methods-xml_methods)}")
    if _policy_signature(DATA_POLICY) != _policy_signature(DEPLOY_POLICY):
        errors.append("data/deploy D-Bus policy 语义不一致；deploy policy 是生产唯一来源，data 仅允许镜像")
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"DBUS_CONTRACT_PASS methods={len(xml_methods)} policy=identical")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

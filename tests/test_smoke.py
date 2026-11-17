"""冒烟测试：不依赖任何 Kali 工具，只验证包能导入、工具能注册、服务能组装。

CI 里跑：python -m pytest -q
"""

from __future__ import annotations

import os
import tempfile

import pytest

from kali_mcp.engine import Engine
from kali_mcp.server import build


@pytest.fixture()
def eng(tmp_path):
    return Engine(str(tmp_path / "data"))


def test_engine_files(eng):
    p = os.path.join(eng.state_dir, "hello.txt")
    eng.write_bytes(p, b"hello kali-mcp")
    assert eng.read_bytes(p) == b"hello kali-mcp"
    assert eng.stat_path(p)["size"] == 16
    assert os.listdir(eng.state_dir)


def test_engine_artifact_and_audit(eng):
    path = eng.save_artifact("unit", "raw output", "echo test")
    assert os.path.isfile(path)
    eng.audit("unit", "did something")
    assert "did something" in eng.history(5)


def test_engine_notes_and_report(eng):
    eng.note_add("22 端口开放", target="10.0.0.5", severity="info", detail="nmap 结果")
    assert "22 端口" in eng.note_list()
    report = eng.report("单测报告")
    with open(report, "r", encoding="utf-8") as fh:
        assert "22 端口" in fh.read()


def test_scope_guard(eng):
    assert eng.in_scope("10.0.0.5") is None          # 未设置范围 -> 不校验
    eng.scope_set(["10.0.0.0/24", "*.example.com"])
    assert eng.in_scope("10.0.0.5") is True
    assert eng.in_scope("10.0.1.5") is False
    assert eng.in_scope("a.example.com") is True


def test_tools_registered(eng):
    mcp = build(eng, token="t", host="127.0.0.1", port=0, path="/mcp")
    tools = mcp._tool_manager.list_tools()
    names = {t.name for t in tools}
    assert len(names) >= 80, f"工具数量偏少: {len(names)}"
    for required in ("kali_status", "kali_exec", "kali_nmap", "kali_nuclei", "kali_report"):
        assert required in names

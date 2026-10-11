"""run_script: only files below the script folder, a dry run by default, and
an answer that says what the script did (SCRIPT-ADAPTER).

The stubbed /runScript answers with the fields GhidraMCPPlugin.runScript
writes; a script that throws is a 200 with ok:false, not an error status.
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest
from mcp.server.fastmcp import FastMCP

from bridge.api.tools import register_tools
from bridge.features import mutations, scripts
from bridge.ghidra.client import RUN_SCRIPT_HTTP_MARGIN_S, GhidraClient
from bridge.tests.plugin_http import plugin_error, plugin_transport
from bridge.utils.errors import UpstreamFailed
from bridge.utils.program_context import PROGRAM_SELECTIONS


def plugin_answer(**overrides) -> dict:
    """/runScript's answer for a script that ran and changed the program."""

    answer = {
        "status": "ok", "ok": True, "script": "Probe.java", "dry_run": True,
        "committed": False, "modified": True, "phase": "run", "timed_out": False,
        "bundle_added": False, "elapsed_ms": 9, "script_error": None,
        "output": "Probe.java> set\n", "output_truncated": False, "output_captured": True,
    }
    answer.update(overrides)
    return answer


class FakeClient:
    def __init__(self, answer=None):
        self.calls = []
        self._answer = answer
        self.last_error = None

    def run_script(self, path, args, *, dry_run, timeout_s):
        self.calls.append((path, list(args), dry_run, timeout_s))
        if callable(self._answer):
            return self._answer(dry_run)
        if self._answer is not None:
            return self._answer
        return plugin_answer(dry_run=dry_run, committed=not dry_run)


@pytest.fixture(autouse=True)
def _clean_ledger():
    mutations.clear()
    yield
    mutations.clear()


@pytest.fixture
def folder(tmp_path: Path) -> Path:
    base = tmp_path / "ghidra_scripts"
    (base / "sub").mkdir(parents=True)
    (base / "Probe.java").write_text("// probe\n")
    (base / "sub" / "Nested.java").write_text("// nested\n")
    (tmp_path / "Outside.java").write_text("// outside\n")
    return base


# --- the folder ---------------------------------------------------------------


def test_without_a_folder_run_script_is_off():
    with pytest.raises(scripts.ScriptUnavailable, match="GHIDRA_MCP_SCRIPT_DIR"):
        scripts.resolve_script(None, "Probe.java")


def test_a_script_in_the_folder_or_below_resolves(folder):
    assert scripts.resolve_script(folder, "Probe.java") == (folder / "Probe.java").resolve()
    assert scripts.resolve_script(folder, "sub/Nested.java") == (folder / "sub/Nested.java").resolve()


@pytest.mark.parametrize("name, message", [
    ("../Outside.java", "leads out"),
    ("sub/../../Outside.java", "leads out"),
    ("Missing.java", "no script"),
    ("sub", "no script"),
    ("", "non-empty"),
])
def test_names_that_are_not_a_file_in_the_folder_are_refused(folder, name, message):
    with pytest.raises(scripts.ScriptRejected, match=message):
        scripts.resolve_script(folder, name)


def test_an_absolute_path_is_refused_even_inside_the_folder(folder):
    with pytest.raises(scripts.ScriptRejected, match="relative"):
        scripts.resolve_script(folder, str(folder / "Probe.java"))


def test_a_symlink_out_of_the_folder_is_refused(folder):
    (folder / "Link.java").symlink_to(folder.parent / "Outside.java")
    with pytest.raises(scripts.ScriptRejected, match="leads out"):
        scripts.resolve_script(folder, "Link.java")


def test_a_symlinked_folder_itself_is_followed(folder, tmp_path):
    link = tmp_path / "scripts_link"
    link.symlink_to(folder)
    assert scripts.resolve_script(link, "Probe.java") == (folder / "Probe.java").resolve()


def test_a_missing_folder_is_unavailable_not_rejected(tmp_path):
    with pytest.raises(scripts.ScriptUnavailable, match="not there"):
        scripts.resolve_script(tmp_path / "nope", "Probe.java")


# --- the run --------------------------------------------------------------------


def test_a_dry_run_runs_the_script_and_proposes_its_change(folder):
    client = FakeClient()
    data = scripts.run_script(client, script_dir=folder, script="Probe.java",
                              args=["0x2af9c4"], writes_enabled=True)

    assert client.calls == [(str((folder / "Probe.java").resolve()), ["0x2af9c4"], True, 60)]
    assert data["ok"] is True and data["applied"] is False and data["modified"] is True
    assert data["output"] == "Probe.java> set\n"
    assert any("rolled back" in n for n in data["notes"])
    [entry] = mutations.since_last_save()
    assert (entry.kind, entry.target, entry.new, entry.applied, entry.reason) == (
        "script", "Probe.java", "0x2af9c4", False, "dry_run")
    assert mutations.render_lines([entry]) == ["[proposed] Probe.java  script    0x2af9c4"]


def test_a_real_run_commits_and_records_it_as_applied(folder):
    client = FakeClient()
    data = scripts.run_script(client, script_dir=folder, script="sub/Nested.java",
                              dry_run=False, timeout_s=5, writes_enabled=True)

    assert client.calls[0][2:] == (False, 5)
    assert data["applied"] is True and data["script"] == "sub/Nested.java"
    [entry] = mutations.since_last_save()
    assert entry.applied is True and entry.new == "(no args)"


def test_writes_disabled_turns_a_real_run_into_a_dry_run(folder):
    client = FakeClient()
    data = scripts.run_script(client, script_dir=folder, script="Probe.java",
                              dry_run=False, writes_enabled=False)

    assert client.calls[0][2] is True
    assert data["applied"] is False and data["dry_run"] is False
    assert any("writes disabled" in n for n in data["notes"])
    assert mutations.since_last_save()[0].reason == "writes_disabled"


def test_a_failed_script_is_a_result_with_its_output_and_no_ledger_entry(folder):
    client = FakeClient(plugin_answer(
        ok=False, modified=True, script_error="IllegalStateException: on purpose",
        output="Probe.java> set\n"))
    data = scripts.run_script(client, script_dir=folder, script="Probe.java",
                              dry_run=False, writes_enabled=True)

    assert data["ok"] is False and data["applied"] is False
    assert data["error"] == "IllegalStateException: on purpose"
    assert data["output"] == "Probe.java> set\n"
    assert any("failed" in n for n in data["notes"])
    assert mutations.since_last_save() == []


def test_a_compile_error_points_at_the_output(folder):
    client = FakeClient(plugin_answer(
        ok=False, modified=False, phase="load", bundle_added=True, output_captured=False,
        script_error="ClassNotFoundException: Probe not found by 23be4d18 [27]",
        output="Probe.java:14: error: ';' expected\n"))
    data = scripts.run_script(client, script_dir=folder, script="Probe.java")

    assert data["phase"] == "load"
    assert any("did not load" in n for n in data["notes"])
    assert any("Bundle Manager" in n for n in data["notes"])
    # the prints were never reached; that is not a capture failure
    assert not any("console" in n for n in data["notes"])


def test_a_runtime_that_is_missing_points_at_the_error(folder):
    client = FakeClient(plugin_answer(
        ok=False, modified=False, phase="load", output="", output_captured=False,
        script_error="GhidraScriptLoadException: Ghidra was not started with PyGhidra. "
                     "Python is not available"))
    data = scripts.run_script(client, script_dir=folder, script="Probe.java")

    assert "PyGhidra" in data["error"]
    assert any("error says why" in n for n in data["notes"])
    assert not any("compiler" in n for n in data["notes"])


def test_a_timeout_says_so(folder):
    client = FakeClient(plugin_answer(ok=False, modified=False, timed_out=True,
                                      script_error="timed out after 3 s"))
    data = scripts.run_script(client, script_dir=folder, script="Probe.java", timeout_s=3)

    assert data["timed_out"] is True
    assert any("timed out" in n for n in data["notes"])


def test_an_unchanged_program_leaves_no_ledger_entry(folder):
    client = FakeClient(plugin_answer(modified=False))
    scripts.run_script(client, script_dir=folder, script="Probe.java")

    assert mutations.since_last_save() == []


def test_a_flag_that_is_not_a_boolean_is_a_failure_not_false(folder):
    client = FakeClient(plugin_answer(committed="false"))
    with pytest.raises(UpstreamFailed, match="committed"):
        scripts.run_script(client, script_dir=folder, script="Probe.java")


def test_a_refused_folder_name_never_reaches_ghidra(folder):
    client = FakeClient()
    with pytest.raises(scripts.ScriptRejected):
        scripts.run_script(client, script_dir=folder, script="../Outside.java")
    assert client.calls == []


# --- the client and the tool ----------------------------------------------------


class FakePlugin:
    def __init__(self, active: str | None = "prog-1") -> None:
        self.active = active
        self.requests: list[httpx.Request] = []
        # The plugin commits a script that ran to its end, unless it is a dry run.
        self.answer = lambda form: httpx.Response(200, json=plugin_answer(
            dry_run=form["dry_run"][0] != "false", committed=form["dry_run"][0] == "false"))

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.lstrip("/")
        if path == "api/current_program.json":
            return httpx.Response(200, json={"domain_file_id": self.active, "locked": False,
                                             "state": "READY", "state_duration_seconds": 5,
                                             "warnings": []})
        if path == "runScript":
            self.requests.append(request)
            return self.answer(parse_qs(request.content.decode()))
        return httpx.Response(404, text="ERROR: not found")


def _client(plugin: FakePlugin) -> GhidraClient:
    return GhidraClient("http://ghidra.test/", transport=plugin_transport(plugin.handle))


def test_the_client_sends_path_args_and_waits_longer_than_the_script():
    plugin = FakePlugin()
    answer = _client(plugin).run_script("/abs/Probe.java", ["0x10", "fail"], dry_run=True, timeout_s=90)

    assert answer["ok"] is True
    (request,) = plugin.requests
    form = parse_qs(request.content.decode())
    assert form["path"] == ["/abs/Probe.java"]
    assert form["args"] == ["0x10 fail"]
    assert form["dry_run"] == ["true"] and form["timeout_s"] == ["90"]
    assert request.url.params["domain_file_id"] == "prog-1"
    assert request.extensions["timeout"]["read"] == 90 + RUN_SCRIPT_HTTP_MARGIN_S


def test_a_request_the_plugin_refuses_raises():
    plugin = FakePlugin()
    plugin.answer = lambda form: plugin_error(404, "NOT_FOUND", "No script file at /abs/Gone.java")
    with pytest.raises(UpstreamFailed, match="No script file"):
        _client(plugin).run_script("/abs/Gone.java", [], dry_run=True, timeout_s=60)


def test_without_an_active_program_nothing_is_sent():
    plugin = FakePlugin(active=None)
    client = _client(plugin)

    assert client.run_script("/abs/Probe.java", [], dry_run=True, timeout_s=60) is None
    assert plugin.requests == []
    assert client.write_refusal is not None


def _tool(plugin: FakePlugin, folder: Path | None, *, enable_writes: bool):
    PROGRAM_SELECTIONS.clear()
    server = FastMCP("script-adapter")
    register_tools(server, client_factory=lambda: _client(plugin),
                   enable_writes=enable_writes, script_dir=folder)
    return server._tool_manager._tools["run_script"].fn


def test_the_tool_runs_a_dry_run_by_default(folder):
    plugin = FakePlugin()
    result = _tool(plugin, folder, enable_writes=True)(script="Probe.java", args="0x2af9c4")

    assert result["ok"] is True, result
    assert result["data"]["applied"] is False
    assert parse_qs(plugin.requests[0].content.decode())["dry_run"] == ["true"]


def test_the_tool_commits_only_with_writes_on_and_dry_run_false(folder):
    plugin = FakePlugin()
    result = _tool(plugin, folder, enable_writes=True)(script="Probe.java", dry_run=False)

    assert result["data"]["applied"] is True
    assert parse_qs(plugin.requests[0].content.decode())["dry_run"] == ["false"]


def test_the_tool_without_a_folder_says_how_to_turn_it_on():
    plugin = FakePlugin()
    result = _tool(plugin, None, enable_writes=True)(script="Probe.java")

    assert result["ok"] is False
    assert "GHIDRA_MCP_SCRIPT_DIR" in json.dumps(result)
    assert plugin.requests == []


def test_the_tool_refuses_a_path_out_of_the_folder(folder):
    plugin = FakePlugin()
    result = _tool(plugin, folder, enable_writes=True)(script="../Outside.java")

    assert result["ok"] is False
    assert result["errors"][0]["code"] == "INVALID_REQUEST"
    assert plugin.requests == []


def test_the_tool_refuses_a_timeout_out_of_range(folder):
    plugin = FakePlugin()
    result = _tool(plugin, folder, enable_writes=True)(script="Probe.java", timeout_s=601)

    assert result["ok"] is False and result["errors"][0]["code"] == "INVALID_REQUEST"
    assert plugin.requests == []


def test_the_tool_answers_a_failed_script_as_a_result(folder):
    plugin = FakePlugin()
    plugin.answer = lambda form: httpx.Response(200, json=plugin_answer(
        ok=False, script_error="IllegalStateException: on purpose"))
    result = _tool(plugin, folder, enable_writes=True)(script="Probe.java")

    assert result["ok"] is True
    assert result["data"]["ok"] is False
    assert result["data"]["error"] == "IllegalStateException: on purpose"

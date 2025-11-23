import inspect
import inspect
import types

from bridge.api.tools import register_tools
from bridge.ghidra.client import GhidraClient


class DummyServer:
    def __init__(self) -> None:
        self.tools = {}

    def tool(self):
        def decorator(fn):
            self.tools[fn.__name__] = fn
            return fn

        return decorator


def dummy_client_factory() -> GhidraClient:
    return types.SimpleNamespace(close=lambda: None)  # type: ignore[return-value]


def test_no_internal_params_exported():
    server = DummyServer()
    register_tools(server, client_factory=dummy_client_factory, enable_writes=False)

    blacklisted = {"client", "request", "state", "context", "scope"}

    for name, fn in server.tools.items():
        sig = inspect.signature(fn)
        exported = list(sig.parameters.values())

        assert not exported or exported[0].name != "client", f"{name} exposes client"

        exported_names = {param.name for param in exported}
        assert exported_names.isdisjoint(blacklisted), (
            f"{name} exports internal params: {exported_names & blacklisted}"
        )

        for param in exported:
            assert param.kind not in {
                inspect.Parameter.VAR_POSITIONAL,
                inspect.Parameter.VAR_KEYWORD,
            }, f"{name} exposes *args/**kwargs"

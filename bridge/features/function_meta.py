"""Reading the plugin's function metadata, which is prose, not fields.

``/get_function_by_address`` answers::

    Function: usbd_init_phy_cep at 002af9c0
    Signature: undefined __stdcall usbd_init_phy_cep(void)
    Entry: 002af9c0
    Body: 002af9c0 - 002afb0f

and the client turns that into ``{"Function": "... at 002af9c0", "Entry":
"002af9c0", ...}``.  There is no ``name`` key, no ``comment`` and no integer
``entry_point``.  Code that read those -- jt.py for the name before and after a
rename, the ARM/Thumb adapter for the entry -- got None every time, and the test
stubs, which returned ``{"name": ...}``, never showed it (JT-PRENAME-PARSE).
"""
from __future__ import annotations

import re
from typing import Any, Mapping, Optional

__all__ = ["function_entry", "function_name", "read_function_name"]

_FUNCTION_PROSE = re.compile(r"^(?P<name>.+) at (?P<address>[0-9a-fA-F]+)$")


def function_name(meta: object, address: int) -> Optional[str]:
    """The function's name, or None when the answer does not say it plainly.

    The value must end in `` at <hex>`` and that hex must be ``address``; a
    name containing `` at `` is handled because the last separator wins.  Any
    other shape yields no guess -- falling back to the whole string would put a
    sentence where a name belongs and read exactly like one.
    """

    if not isinstance(meta, Mapping):
        return None
    described = meta.get("Function") or meta.get("function")
    if isinstance(described, str) and described.strip():
        match = _FUNCTION_PROSE.match(described.strip())
        if match is None or int(match.group("address"), 16) != address:
            return None
        return match.group("name").strip() or None
    # Tolerate a plugin that grows a proper field later.
    plain = meta.get("name")
    return plain if isinstance(plain, str) and plain.strip() else None


def function_entry(meta: object) -> Optional[int]:
    """The entry point: ``Entry`` (hex text) from the plugin, or an int field."""

    if not isinstance(meta, Mapping):
        return None
    for key in ("Entry", "entry_point", "address"):
        value: Any = meta.get(key)
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.strip():
            try:
                return int(value.strip(), 16)
            except ValueError:
                return None
    return None


def read_function_name(client: Any, address: int) -> Optional[str]:
    """Ask the plugin and parse; None on any failure.  Never raises -- a ledger
    or a verification step must not break the write it describes."""

    try:
        meta = client.get_function_by_address(address)
    except Exception:  # noqa: BLE001
        return None
    return function_name(meta, address)

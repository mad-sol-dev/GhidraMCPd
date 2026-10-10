"""project_info carries enough provenance to tell which bytes an answer came from.

The plugin reports every imported file twice -- as imported and as it stands now --
and maps each memory block to a file offset with a digest of its contents. These
tests pin the schema side of that contract: the fields are accepted, a malformed
digest is not, and a plugin built before the fields existed still validates.
"""

from __future__ import annotations

import copy

from bridge.api.validators import validate_payload
from bridge.utils.config import WRITES_ENABLE_HOWTO

_SHA_A = "a" * 64
_SHA_B = "b" * 64


def _payload() -> dict:
    return {
        "program_name": "ZK-INKJET-NANO-APP.bin.orig",
        "executable_path": "/fw/ZK-INKJET-NANO-APP.bin.orig",
        "executable_md5": "0" * 32,
        "executable_sha256": _SHA_A,
        "executable_format": "Raw Binary",
        "image_base": "0x00200000",
        "language_id": "ARM:LE:32:v5t",
        "compiler_spec_id": "default",
        "entry_points": ["0x00200000"],
        "source_files": [
            {
                "name": "ZK-INKJET-NANO-APP.bin.orig",
                "size": 2577964,
                "original_sha256": _SHA_A,
                "modified_sha256": _SHA_A,
                "patched": False,
            }
        ],
        "memory_blocks": [
            {
                "name": "flash",
                "start": "0x00200000",
                "end": "0x0047522b",
                "length": 2577964,
                "rwx": "r-x",
                "loaded": True,
                "initialized": True,
                "source_file_index": 0,
                "file_offset": 0,
                "sha256": _SHA_A,
            }
        ],
        "imports_count": 0,
        "exports_count": None,
        "writes_enabled": False,
        "writes_note": WRITES_ENABLE_HOWTO,
    }


def test_provenance_fields_validate() -> None:
    valid, errors = validate_payload("project_info.v1.json", _payload())
    assert valid, errors


def test_patched_program_validates_and_says_so() -> None:
    payload = _payload()
    payload["source_files"][0]["modified_sha256"] = _SHA_B
    payload["source_files"][0]["patched"] = True
    payload["memory_blocks"][0]["sha256"] = _SHA_B
    valid, errors = validate_payload("project_info.v1.json", payload)
    assert valid, errors


def test_unreadable_digest_is_null_not_absent() -> None:
    payload = _payload()
    payload["source_files"][0]["modified_sha256"] = None
    payload["source_files"][0]["patched"] = None
    payload["memory_blocks"][0].update(source_file_index=None, file_offset=None, sha256=None)
    valid, errors = validate_payload("project_info.v1.json", payload)
    assert valid, errors


def test_uppercase_or_short_digest_is_rejected() -> None:
    for bad in ("A" * 64, "a" * 63):
        payload = _payload()
        payload["source_files"][0]["original_sha256"] = bad
        valid, _ = validate_payload("project_info.v1.json", payload)
        assert not valid, bad


def test_source_file_requires_patched() -> None:
    payload = _payload()
    del payload["source_files"][0]["patched"]
    valid, _ = validate_payload("project_info.v1.json", payload)
    assert not valid


def test_plugin_without_provenance_still_validates() -> None:
    """An extension built before the fields existed must not break project_info."""
    payload = copy.deepcopy(_payload())
    del payload["source_files"]
    for block in payload["memory_blocks"]:
        for key in ("source_file_index", "file_offset", "sha256"):
            del block[key]
    valid, errors = validate_payload("project_info.v1.json", payload)
    assert valid, errors

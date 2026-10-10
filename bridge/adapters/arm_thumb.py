"""ARM/Thumb adapter implementation."""
from __future__ import annotations

from dataclasses import dataclass

from . import ArchAdapter, Probe
from ..features.function_meta import function_entry

BX_SENTINELS = {0xE12FFF1C, 0xE12FFF33}


@dataclass(slots=True)
class ARMThumbAdapter(ArchAdapter):
    code_alignment: int = 4

    def in_code_range(self, ptr: int, code_min: int, code_max: int) -> bool:
        return code_min <= ptr < code_max

    def is_instruction_sentinel(self, raw: int) -> bool:
        return raw in BX_SENTINELS

    def probe_function(
        self, client, ptr: int, code_min: int, code_max: int
    ) -> Probe:
        # Bit 0 set is a Thumb pointer (interworking); ARM code is word-aligned.
        # An odd ARM target used to be ruled out only by accident, when the
        # old disassembly check happened to fail there.
        candidates: list[tuple[str, int]] = []
        if ptr % self.code_alignment == 0 and self.in_code_range(ptr, code_min, code_max):
            candidates.append(("ARM", ptr))
        thumb_target = ptr - 1
        if ptr & 1 and thumb_target >= 0 and self.in_code_range(thumb_target, code_min, code_max):
            candidates.append(("Thumb", thumb_target))
        seen: set[int] = set()
        for mode, target in candidates:
            if target < 0 or target in seen:
                continue
            seen.add(target)
            if self._verify_candidate(client, target):
                return mode, target
        return None, None

    def _verify_candidate(self, client, target: int) -> bool:
        """A function starts at ``target``.

        Asked of /get_function_by_address, which matches entry points only.
        "Can it be disassembled" is no answer: /disassemble_function finds the
        function *containing* an address, and its failure prose ("No function
        found at or containing ...") is a non-empty list -- so every in-range
        target used to pass.
        """

        meta = client.get_function_by_address(target)
        return function_entry(meta) == target


__all__ = ["ARMThumbAdapter"]

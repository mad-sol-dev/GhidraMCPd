"""The regression this project paid seven months for.

``search_scalars("0xB1008000")`` returns nothing on ZK-INKJET-NANO-APP.bin.  The
value is there: it sits at ``0x002AFB4C`` in a constant pool, reached by a
PC-relative load, where an operand search cannot see it.  Reading that empty
result as a statement about the firmware blocked the USB path.

Step 1 -- an empty result carrying a method_note -- is explicitly *not* enough to
pass.  Step 2 executes the path the note names and must arrive at the value.  A
note that sounds right but leads nowhere would be the same failure wearing a
different hat.
"""
from __future__ import annotations

import re

import pytest

from bridge.api.validators import validate_payload
from bridge.features import batch_ops, scalars, search_function
from bridge.features.method_notes import METHOD_NOTES

#: The value that came back empty, and where it actually lives.
MISSING_VALUE = "0xB1008000"
USBD_BA = 0x002AFB4C
USBD_BA_PLUS_704 = 0x002AFB40
USBD_BA_PLUS_704_VALUE = 0xB1008704

#: A function that loads from the pool holding those words.
LOADER = 0x002AF9C0
POOL = 0x002AFB34

#: 'ldr r1,[0x2afb34]' -- the pool address inside the operand.
_POOL_OPERAND = re.compile(r"\[0x([0-9a-fA-F]{4,})\]")


@pytest.fixture(scope="module")
def empty_scalar_search(client):
    return scalars.search_scalars(client, value=MISSING_VALUE, query="", limit=100, page=1)


# --------------------------------------------------------------------- step 1

def test_the_search_really_does_come_back_empty(empty_scalar_search):
    # No total: search_scalars pages by cursor and never reports one, so an
    # empty result is stated as returned == 0 rather than total == 0.
    assert empty_scalar_search["returned"] == 0
    assert empty_scalar_search["items"] == []
    assert "total" not in empty_scalar_search


def test_the_empty_result_carries_a_method_note(empty_scalar_search):
    note = empty_scalar_search.get("method_note")
    assert note, "an empty scalar search must say what it cannot see"
    assert "operand" in note
    assert "constant pool" in note


def test_the_note_still_validates_against_the_response_schema(empty_scalar_search):
    """The note must survive the schema, or the MCP tool would reject it."""

    valid, errors = validate_payload("search_scalars.v1.json", empty_scalar_search)
    assert valid, errors


def test_a_search_with_hits_carries_no_note(client):
    """The note marks a negative finding; on a hit it would be noise.

    Note that ``total`` is absent here: with a small limit the search paginates
    by cursor and does not know the total.  "attach a note when total == 0" would
    therefore have been the wrong rule on its own -- the emptiness of the result
    list has to decide when the total is unknown.
    """

    found = scalars.search_scalars(client, value="0x1000", query="", limit=5, page=1)
    assert found["items"], "0x1000 should appear as an operand somewhere"
    assert "total" not in found or found["total"] > 0
    assert "method_note" not in found


# --------------------------------------------------------------------- step 2

def test_the_note_names_the_tools_it_expects_you_to_use(empty_scalar_search):
    note = empty_scalar_search["method_note"]
    assert "find_in_function" in note
    assert "read_words" in note


def test_the_named_path_reaches_the_constant_pool(client):
    """First leg: find_in_function with 'ldr' exposes the pool address.

    The pool address is read out of the operand, not assumed -- that is the
    step a reader would perform, so it is the step under test.
    """

    matches = search_function.find_in_function(client, address=LOADER, query="ldr")
    lines = [
        entry["matched_text"]
        for entry in matches["matches"]["disassembly"]
        if entry.get("matched_text")
    ]
    assert lines, "the loader function should contain ldr instructions"

    pools = {int(m.group(1), 16) for line in lines for m in _POOL_OPERAND.finditer(line)}
    assert POOL in pools, f"expected the pool at {POOL:#010x}, found {sorted(pools)}"


def test_the_named_path_finds_the_value_the_search_missed(client):
    """Second leg: read_words on the pool returns what search_scalars could not.

    This is the assertion that makes the whole exercise worth anything.
    """

    words = batch_ops.read_words(client, address=POOL, count=10)["words"]
    # Words come back as hex strings: these are register addresses, and a
    # transcription error is visible in hex and invisible in decimal.
    by_address = {
        POOL + 4 * index: (None if value is None else int(value, 16))
        for index, value in enumerate(words)
    }

    assert by_address[USBD_BA] == int(MISSING_VALUE, 16), (
        f"{USBD_BA:#010x} should hold {MISSING_VALUE}, "
        f"got {by_address[USBD_BA]:#010x}"
    )
    assert by_address[USBD_BA_PLUS_704] == USBD_BA_PLUS_704_VALUE, (
        f"{USBD_BA_PLUS_704:#010x} should hold USBD_BA+0x704"
    )


def test_step_two_is_not_optional(client, empty_scalar_search):
    """Guard against the failure mode this whole test exists to prevent.

    If the note ever stops naming a working path, step 1 alone would still be
    green -- an empty result with a plausible-sounding note.  This ties the two
    together explicitly.
    """

    assert empty_scalar_search["returned"] == 0
    alternative = METHOD_NOTES["search_scalars"].alternative
    assert "find_in_function" in alternative
    assert "read_words" in alternative

    words = batch_ops.read_words(client, address=POOL, count=10)["words"]
    assert MISSING_VALUE.lower() in [w.lower() for w in words if w]


# ------------------------------------------------------- the other search tools

def test_every_search_tool_with_a_note_emits_it_when_empty(client):
    """The rule is "every search tool", not "search_scalars".

    Each of these is driven to an empty result on the live program and must come
    back carrying its note.
    """

    from bridge.features import functions, strings, xrefs

    empty_results = {
        "search_functions": functions.search_functions(
            client, query="zzzzznope", limit=10, page=1
        ),
        "search_strings": strings.search_strings(
            client, query="zzzzznope", limit=10, page=1
        ),
        "search_scalars_with_context": batch_ops.search_scalars_with_context(
            client, value=int(MISSING_VALUE, 16), context_lines=2, limit=10
        ),
    }

    for tool, payload in empty_results.items():
        assert payload["returned"] == 0, tool
        assert payload.get("method_note"), f"{tool} returned nothing and said nothing"
        assert payload["method_note"] == METHOD_NOTES[tool].as_text(), tool


def test_xrefs_with_hits_stays_quiet(client):
    from bridge.features import xrefs

    found = xrefs.search_xrefs_to(client, address="0x00200000", query="", limit=10, page=1)
    assert found["total"] > 0
    assert "method_note" not in found


# ------------------------------------------------------------- search_imports

def test_search_imports_no_longer_fails_on_this_program(client):
    """The Stage 0 side finding: one import, in the EXTERNAL address space.

    It made search_imports return INVALID_REQUEST on the main program for every
    query that matched it.
    """

    from bridge.api.validators import validate_payload
    from bridge.features import imports

    payload = imports.search_imports(client, query="e", limit=20, page=1)

    valid, errors = validate_payload("search_imports.v1.json", payload)
    assert valid, errors

    addresses = [item["address"] for item in payload["items"]]
    assert "EXTERNAL:00000001" in addresses, payload


# ------------------------------------------------------------- Stage 3 contract

def test_an_unknown_total_is_absent_rather_than_null(client):
    """A cursor-paged search does not know the total, and must not pretend to.

    Reporting null would leave a caller reading `data["total"]` a value that
    looks like an answer; omitting the key makes the absence of knowledge
    explicit, at the cost of breaking exactly that kind of caller -- which is
    the point.
    """

    from bridge.features import scalars

    paged = scalars.search_scalars(client, value="0x1000", query="", limit=5, page=1)
    assert "total" not in paged, paged.get("total")
    assert paged["truncated"] is True
    assert paged["has_more"] is True


def test_a_complete_result_reports_its_total_and_is_not_truncated(client):
    """Where the total is genuinely known it is still reported."""

    from bridge.features import imports

    complete = imports.search_imports(client, query="e", limit=20, page=1)
    assert complete["total"] == 1
    assert complete["truncated"] is False
    assert complete["has_more"] is False


# --------------------------------------------- Stage 4: the batch filter, live

#: The four functions the reference session walks through.
BATCH_FUNCTIONS = ["0x002af9c0", "0x002af80c", "0x0026a7f8", "0x0025b0c4"]


def test_the_batch_filter_answers_the_real_question(client):
    """"Every constant-pool load in these four functions", in one call.

    Without a filter that is 64 instructions to read 11 of them.
    """

    from bridge.features import batch_ops

    unfiltered = batch_ops.disassemble_batch(
        client, addresses=BATCH_FUNCTIONS, count=16, fmt="text"
    )
    scanned = sum(len(lines) for lines in unfiltered["results"].values())
    assert scanned == 64

    filtered = batch_ops.disassemble_batch(
        client,
        addresses=BATCH_FUNCTIONS,
        count=16,
        fmt="text",
        query=r"ldr \w+,\[0x",
        regex=True,
    )
    assert filtered["summary"] == {"scanned": 64, "matched": 11, "returned": 11}

    lines = [line for lines in filtered["results"].values() for line in lines]
    assert len(lines) == 11
    assert all("ldr" in line for line in lines)
    # The pool the Stage 2 regression walks to, found here in one call.
    assert any("0x2afb34" in line for line in lines)


def test_without_a_query_the_response_is_unchanged(client):
    """The filter must be additive, not a behaviour change."""

    from bridge.features import batch_ops

    plain = batch_ops.disassemble_batch(
        client, addresses=BATCH_FUNCTIONS, count=16, fmt="json"
    )
    assert set(plain) == {"addresses", "count", "results"}
    assert "filter" not in plain
    assert "summary" not in plain
    assert sum(len(items) for items in plain["results"].values()) == 64


def test_the_filtered_response_still_validates(client):
    from bridge.api.validators import validate_payload
    from bridge.features import batch_ops

    for fmt in ("json", "text"):
        payload = batch_ops.disassemble_batch(
            client,
            addresses=BATCH_FUNCTIONS,
            count=16,
            fmt=fmt,
            query="ldr r",
            context_lines=2,
        )
        valid, errors = validate_payload("disassemble_batch.v1.json", payload)
        assert valid, (fmt, errors)
        assert payload["summary"]["returned"] > payload["summary"]["matched"]

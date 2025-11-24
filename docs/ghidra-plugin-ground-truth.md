# Ghidra Plugin Ground Truth (for MCP Integration)

This page defines **exact request/response formats** for the Java plugin (plain text on port 8080) and the **Ghidra APIs** you’ll typically touch. Follow this spec to keep the Python features, HTTP routes, and MCP tools working deterministically.

## Conventions

* **Port:** 8080 (plugin), **Content-Type:** `text/plain; charset=UTF-8`
* **Encoding:** ASCII/UTF-8 (avoid umlauts), one **record per line**
* **Sorting:** always **ascending by address** *before* applying limits
* **Caps:** `limit ≤ 500`, `count ≤ 128` (disassembly), `length ≤ 4096` (bytes)
* **Errors:** on invalid params return **HTTP 400** with a single line: `error: <reason>`
* **Pagination:** the plugin returns the **full list**; Python does filter/sort/paginate to `total/page/limit`
* **List endpoints:** support `offset` and `limit` parameters for pagination

## Direct HTTP endpoints

Raw plugin routes are exposed on **port 8080** for non-MCP access:

* `/methods`
* `/classes`
* `/segments`
* `/imports`
* `/exports`
* `/namespaces`
* `/data`
* `/functions`
* `/strings`
* `/read_bytes`
* `/read_dword`
* `/read_cstring`
* `/disassembleAt`
* `/disassemble`
* `/renameFunction`
* `/renameVariable`
* `/renameData`
* `/set_*comment`
* `/rename_function_by_address`
* `/set_function_prototype`
* `/set_local_variable_type`

---

## Endpoints (text formats)

### 1) `/searchScalars?value=0xNNNN[&limit=N]`  — find immediates/constants

* **Params:** `value` (hex `0x…` or decimal), optional `limit` (cap 500)
* **Response (one hit per line):**

  ```
  0xADDRESS: <disassembly text>
  ```

  Examples:

  ```
  0x0020A1C0: LDR R0, =0xB0000084
  0x0020A234: STR R1, [R2, #0xB8001010]
  ```

  Notes:

  * First token is the **address**, followed by `:`, then free disassembly text.
  * The Python client fills in `value` and (optionally) the function name itself.
  * Scans honor **cancellation** and a **hard inspection cap (500k instructions across all functions checked)**.
    * If cancellation or the cap triggers mid-scan, the HTTP 200 body still returns **all accumulated matches**.
    * When the cap is hit, the envelope includes an `error` field explaining the cap and how many instructions were inspected; clients should surface that message.

---

### 2) `/functionsInRange?min=0xMIN&max=0xMAX`

* **Params:** `min`, `max` (hex)
* **Response (one function per line):**

  ```
  <name> @ 0xADDRESS [size]
  ```

  Examples:

  ```
  init_board @ 0x00201000 128
  FUN_0020345C @ 0x0020345C
  ```

  Notes:

  * `size` is optional; if unknown, omit it.
  * Address must be `0x`-hex.

---

### 3) `/disassembleAt?address=0xNNNN[&count=N]`

* **Params:** `address` (hex), optional `count` (cap 128, default 16)
* **Response (one instruction per line):**

  ```
  0xADDRESS: BYTESHEX <disassembly text>
  ```

  Examples:

  ```
  0x00201000: E59F0010 LDR R0, [PC, #0x10]
  0x00201004: E3A01001 MOV R1, #1
  ```

  Notes:

  * `BYTESHEX` is a continuous uppercase hex string of the instruction bytes.

---

### 4) `/readBytes?address=0xNNNN&length=N`

* **Params:** `address` (hex), `length` (cap 4096)
* **Response:** **one line** containing **only Base64 data** (no prefixes).

  ```
  AAECAwQFBgcICQ==
  ```

  Notes:

  * Python decodes this and re-emits MCP/HTTP JSON as `{encoding:"base64", data:"…"}`.

---

### 5) **MMIO annotate** (existing)

If your plugin emits MMIO samples, include an **absolute address** field wherever possible:

```
... address_abs=0xB0000084 ...
```

The Python feature already exposes `address_abs` in its JSON; having it directly from the plugin is ideal.

---

## Ghidra API cheat-sheet (what you’ll likely use)

* **Listing / Instruction / Scalar**

  * `Program.getListing()`
  * `Listing.getInstructions(boolean forward)`
  * `Listing.getInstructionAt(Address)`
  * `Instruction.getBytes()`, `Instruction.toString()`
  * `Instruction.getOpObjects(int)` → check for `Scalar` and compare unsigned values
* **FunctionManager**

  * `Program.getFunctionManager()`
  * `getFunctionContaining(Address)`
  * `getFunctions(AddressSetView, boolean forward)` (for range queries)
* **Addressing**

  * `AddressFactory.getDefaultAddressSpace().getAddress(long)`
  * `AddressSet(min, max)` to build inclusive ranges
* **Memory**

  * `Program.getMemory().getBytes(Address, byte[])`
* **(Optional) References**

  * `Program.getReferenceManager().getReferencesTo(Address)` if you extend xref features later

---

## Implementation tips & pitfalls

* **Determinism:** explicitly sort by address ascending before applying caps/limits. This keeps contract/golden tests stable.
* **Address space:** read/disassemble from the correct `AddressSpace` (no overlays unless intended).
* **Performance:** scanning all instructions is fine for now; for huge programs consider task monitors to avoid UI stalls.
* **Immediates:** ARM/Thumb often materialize constants across multiple instructions. For P1 we match `Scalar` operands directly; smarter PC-relative reconstruction can be a future enhancement.

---

## Minimal handler pattern (pseudo-skeleton)

```java
void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    resp.setCharacterEncoding("UTF-8");
    resp.setContentType("text/plain; charset=UTF-8");
    try {
        switch (req.getPathInfo()) {
            case "/searchScalars":    respond(resp, handleSearchScalars(program, req)); break;
            case "/functionsInRange": respond(resp, handleFunctionsInRange(program, req)); break;
            case "/disassembleAt":    respond(resp, handleDisassembleAt(program, req)); break;
            case "/readBytes":        respond(resp, handleReadBytes(program, req)); break;
            default: resp.setStatus(404); resp.getWriter().println("error: not found");
        }
    } catch (IllegalArgumentException e) {
        resp.setStatus(400);
        resp.getWriter().println("error: " + e.getMessage());
    }
}
```

---

## How to validate quickly

1. Hit each endpoint with a small sample (e.g., `value=0xB0000084`, a known address range, etc.).
2. Confirm outputs match the **line formats** above exactly.
3. Run the Python suite:
   `python -m pytest -q bridge/tests/unit bridge/tests/contract bridge/tests/golden`
4. In MCP discovery, ensure tools are available and take **only** their functional parameters (no `client`, no `*args/**kwargs`).


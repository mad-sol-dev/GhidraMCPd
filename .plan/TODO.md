# Ghidra MCP – TODO (authoritative)

> Goal: LLM-friendly, token-efficient server. Fewer round trips through Composite Ops and Multi-Query Collector.
> Standards: 1-based `page`, `has_more`, deterministic sorting, strict envelope `{ok,data,errors[]}`.

## NOW
- {R.22} Data type lookup cache for Ghidra plugin (per-DataTypeManager map with safe invalidation and fast lookup fallback)
- {R.23} `open_program` readiness semantics (IDLE/LOADING/READY state + status endpoint + bridge polling)
- {R.25} Default read-only mode (`GHIDRA_MCP_ENABLE_WRITES` false) with `/info` reflecting write enablement and user guidance
- {R.26} Write endpoint `domain_file_id` validation against the active program (reject mismatches before mutating)

Recommended next focus: land {R.22}/{R.23} to improve plugin performance and readiness gating before tackling remaining NEXT items.

## NEXT
- {RESPONSE-VALIDATION-MISLABELED} **Eine fehlgeschlagene Antwort-Validierung wird dem Aufrufer als `INVALID_REQUEST` gemeldet.** An 29 Stellen in `bridge/api/tools.py` folgt auf `validate_payload("<tool>.v1.json", data)` ein `envelope_error(ErrorCode.INVALID_REQUEST, ...)`. Verletzt die Antwort ihr eigenes Schema, ist das ein Serverfehler, keine schlechte Anfrage — der Aufrufer sucht dann in seinen Parametern nach einem Fehler, den er nicht gemacht hat. Genau so trat {COLLECT-METADATA-REJECTED} in Erscheinung. `ErrorCode.INTERNAL` existiert bereits. Zu klären: einheitlich umstellen, und ob Bestandstests auf `INVALID_REQUEST` prüfen. Gefunden 2026-08-31 beim Beheben von {COLLECT-METADATA-REJECTED}.
- {MMIO-ZERO-TARGET} `mmio_annotate_compact` meldet eine bitweise Operation ohne Immediate (`and r0,r0,r1`) als `target 0x00000000`, und `address_abs` fällt dann auf die Instruktionsadresse zurück. Liest sich wie „UND mit 0". Das Antwortschema verlangt einen Hex-String; `null` erlauben ist eine Schemaänderung für beide Projekte. Alt, nicht aus 8c; dort sichtbar geworden.
- {DEAD-ALIAS-FIRST} Tote Alias-Namen vorn in der Kandidatenliste kosten pro Aufruf eine 404: der Client wird pro Tool-Aufruf neu gebaut, der Resolver-Cache überlebt nichts. `FUNC_BY_ADDR` beginnt mit `function_by_addr`, `GET_XREFS_TO` mit `get_xrefs_to` — beide existieren im Plugin nicht. Lebenden Namen nach vorn oder tote streichen; `test_plugin_routes.py` kennt die Routen. Gefunden 2026-10-09 in Stufe 8b.
- {R.24} Port 8080 error response cleanup (consistent text/JSON conventions and bridge parsing alignment)
- {R.29} Character/token-based result limits for analyze_function_complete (replace or supplement line-based truncation with char/token budgets to avoid mid-block cutoffs)
- {R.9} Firmware-set workflows (boot→app→res prompts, swap-back guidance)
- {R.11} LLM recipes on existing tools (string→xrefs→disasm, scalar→MMIO→annotate, region→functions→analyze)
- {R.13} Extension ZIP packaging + install checklist + CI/script smoke-test hook
- {R.17} AGENTS.md guidance for ghidra-bridge usage and prompting defaults
- {R.18} Cookbook snippets for USB/update/boot/MMIO workflows using MCP tools only
- {R.27} LLM-visible comment tagging/prefixing for write calls (toolname/LLM annotations and format guidance)
- {R.28} Audit logging for write operations (inputs, program context, and response outcomes with redaction rules)
- {DIAG.3} Force-refresh endpoint for manual state re-checking (allow users to trigger trackProgram() when state appears stale)
- {DIAG.4} Analysis completion metadata in search results (add analysis_complete flag based on AutoAnalysisManager state)
- {BUILD.1} Docker cache workaround documentation (docker build --no-cache or version-tagged images to avoid stale builds)
- {JT-PRENAME-PARSE} jt.py parst pre_name/pre_comment falsch
- {ANALYZE-POOL-CONSTANTS} Konstantenpool-Worte als eigener Abschnitt
- {FIND-IN-FUNCTION-TEXT} fmt="text" fuer find_in_function
- {DOC-DEFAULT-DRIFT} Test: Doku gegen Signatur-Defaults
- {IMAGE-BASE-STALE} `image_base` meldet am ZK-Inkjet-Programm 0x00000000, der einzige Block liegt bei 0x00200000; 16 Einsprungpunkte bei 0x0/0xFFFF0000 zeigen auf nicht gemappten Speicher (ZK-Repo: Ghidra nimmt High Vectors an, CL-TOOL-REC-121). Die Linkbasis ist laut ZK-Repo 0x00058000 (CL-BOOT-REC-113), weder image_base noch Blockstart. Klaeren, ob das Programm korrigiert oder `project_info` die Abweichung melden soll. Gefunden 2026-10-08.

## LATER
- {R.5} CORS/origin whitelist controls for bridge endpoints
- {R.6} Docker images + CI packaging handoff
- {R.7} MCP tool UX docs (flows, screenshots, failure drills)
- {R.14} Ghidra version-compat matrix (min vs. latest, mock-based type checks)
- {R.19} Cross-binary analysis (BOOT⇄APP links, firmware diffing)
- {R.20} Controlled Ghidra action automation (auto-analysis, mark-as-library) with confirmations

## DONE
- [x] {R.12} `apply_label`: Plugin-Route `POST /createLabel` und Tool mit `dry_run`-Default und Schreibsperre; setzt Labels auch ohne definierte Daten (MMIO). Live verifiziert 2026-10-10 mit Plugin 1.3.57 an 0xB1006000 (anlegen, zurücklesen, kein Duplikat beim zweiten Mal; danach in Ghidra zurückgenommen, Programm ohne ungespeicherte Änderungen). `scripts/ghidra/import_mmio_labels.py` dupliziert bei erneutem Lauf nicht mehr (zk-inkjet CL-TOOL-REC-122: alle 96 importierten Register stehen dort doppelt).
- [x] {STAGE-8} Naht Plugin↔Bridge: 8a Loopback-Bind, 8b Phantom-Tools entfernt, 8c Disassemblat als Struktur (mmio/analyze/strings lesen Felder), 8d `/functionsInRange` als JSON. Abgenommen 2026-10-10 mit Plugin 1.3.56, Ergebnisse in `ghidramcpd-rework.md`, Stufe 8.
- [x] {MMIO-STALE-BASE} `mmio_annotate_compact` liest Adressen aus Ghidras Referenzen (Stufe 8c). An 0x002AF9C0 alle 28 Zugriffe = Ghidras Referenzen, die fünf alten Fehladressen korrigiert; Live-Test `bridge/tests/live/test_mmio_stale_base_live.py`, gegen den alten Stand rot.
- [x] {PLAN-TESTS-RED} `bridge/tests/plan` wieder grün: `STAGE-8`, `IMAGE-BASE-STALE`, `DEAD-ALIAS-FIRST` in `state.json` und Manifest nachgetragen, `AGENT_LOCK`-Lease auf `main` bis 2026-10-23 verlängert. Der Lease-Test schlägt nach Ablauf erneut an — so gebaut, kein Fehler.
- [x] {PROJECT-INFO-PROVENANCE} `project_info` belegt, welche Bytes antworten: `source_files` mit SHA-256 wie importiert und wie aktuell (`patched`), je Block `file_offset`, `source_file_index` und SHA-256 des Inhalts. Muster aus REAs Ghidra-Bridge (MIT). Verifiziert 2026-10-08 am ZK-Inkjet-Programm: alle vier Hashes = `3be9028b…` = `firmware/bin/ZK-INKJET-NANO-APP.bin`, `patched=false`, `flash` @0x00200000 = Dateioffset 0.
- [x] {COLLECT-METADATA-REJECTED} `metadata` steht im Antwortschema von `collect`; der dokumentierte Parameter kommt unveraendert zurueck, statt die eigene Antwort ungueltig zu machen.
- [x] {READ-BYTES-NOTE-WORDING} `read_bytes` beschreibt die kurze Antwort, nicht Nullen, die es dort nicht gibt.
- [x] {FUNC-CHUNKS-THUNKS} `/functionsInRange?fields=extended` liefert Body-Spanne, `thunk=` und `chunks=`; Bridge zeigt `is_thunk`/`thunk_to`/`span_bytes`/`chunks` nur, wo sie etwas aussagen. Gegen das laufende Programm verifiziert (Thunk-Ziel, Chunks, Spanne).
- [x] {DISASM-SILENT-SKIP} Undefinierte Bereiche werden nicht mehr verschwiegen — `coverage` + `method_note` in `disassemble_at`/`disassemble_batch`, `unreadable_words`/`method_note` in `read_words`/`read_bytes`. Verifiziert 2026-08-31 am ZK-Inkjet-Programm, alle vier Endpunkte mit Positivkontrolle: `disassemble_at`/`disassemble_batch` melden 21652 uebersprungene Bytes ab 0x281900 und 148 ab 0x280AE8, `read_words`/`read_bytes` melden 0x7D8 als nicht gemappt; definierter Code (0x25B0C4) und gemappte Pooladresse (0x2AFB4C) bleiben ohne Zusatzmeldung.
- [x] {FUNC-BOUNDS-DISAGREE} `size` und `range` sind definiert und gehen auf: `range.span_bytes` (Spanne, Innendaten eingeschlossen) gegen `size` (Rumpfbytes); Differenz ist das Pool-Loch, das `coverage` jetzt meldet.
- [x] {R.21} Single-port multi-context server (Java singleton, FrontEnd loading, dispatching, open_program)
- [x] {R.10} Clarify `strings_compact` population and error contracts (incl. `search_xrefs_to` empty-query behavior)
- [x] {R.8} Program selection helpers (`select_program`, `get_current_program`) to anchor analysis tools on the active Ghidra program
- [x] {D.1} GET /api/project_info.json (read-only) — deterministic metadata envelope, contract/unit coverage, docs snapshot updated.
- [x] {D.2} POST /api/analyze_function_complete.json (read-only) — composite dossier (`fields`, `fmt`, `max_result_tokens`, disasm/decompile/xrefs/callgraph/strings/features) with deterministic ordering, unit/contract/golden coverage, docs updated.
- [x] {D.5} Error schema + enums — unified error envelope `{status,code,message,recovery[]}`, updated docs, contract/unit/golden coverage.
- [x] {D.3} Unify search metadata — {query,total,page,limit,has_more,items} now consistent across list/search endpoints (range + pagination edge cases covered).
- [x] {D.4} POST /api/collect.json — multi-query collector with per-subop envelopes, request budgeting, docs/tests updated.
- [x] {T-202511-018} Sync roadmap + plan docs with audit — ROADMAP.md updated, `.plan` statuses aligned, overview captures current capabilities.
- [x] {D.6} Result budgeting — request/query `max_result_tokens`, auto-trim (200) vs strict (413) enforcement, coverage + docs refreshed.
- [x] {D.7} rank=simple & k — heuristic prefilter enabled as opt-in, stable ordering, docs/tests added.
- [x] {D.8} Cursor streaming for very large sets — cursor/resume plumbing landed with docs/tests.
- [x] {D.9} 5-min short-term cache per {digest,query}.
- [x] OpenAPI renderer fixed — gen_api_md.py handles 3.1 unions/combinators, docs regenerated.
- [x] Maven deps via GHIDRA_DIR — CI downloads Ghidra, pom.xml uses GHIDRA_DIR system paths, docs note local build.
- [x] {R.1} Batch project analysis lanes for multi-program dossiers — collector lanes span multiple Ghidra projects with deterministic envelopes and docs/tests.
- [x] {R.2} Enhanced search ranking + expanded context windows — function search supports opt-in context windows with deterministic ordering coverage across unit/contract/golden suites.
- [x] {R.3} `include_literals` plumbing across memory and string search endpoints.
- [x] {R.4} Expanded audit logging for write/rebase/datatypes flows.
- [x] {T-202511-019} Refresh roadmap and .plan with navigation/context/backlog alignment.
- [x] {R.15} MCP tool smoke-test script against reference firmware (project_info/overview, strings, scalars, MMIO, bytes/words).
- [x] {R.16} Unit-test expansion for new project/analysis tools and invalid-parameter paths.

## Invariants
- CI green (Unit/Contract/Golden), OpenAPI drift-free.
- Breaking defaults only via minor bump.

# ghidraMCPd — Rework in Stufen

Arbeitsanweisung für eine Claude-Code-Sitzung. Grundlage: Review der 35 Tool-Schemata
vom 2026-08-20.

**Einstiegsnachricht für den neuen Chat (wörtlich):**

> Repo `GhidraMCPd`. Lies `ghidramcpd-rework.md` und arbeite
> die Stufen der Reihe nach ab. Stufe 0 zuerst, keine Stufe überspringen. Nach jeder
> Stufe: Abnahmekriterium prüfen, committen, mir berichten. Keine Umbauten, die nicht
> in einer Stufe stehen.

---

## Rahmenbedingungen

Diese gelten für jede Stufe.

1. **Der Server bedient mehrere Projekte.** Mindestens `zk-inkjet-ghidramcpd` und
   `starfish-ghidramcpd` laufen gegen dieselbe Codebasis. Jede Verhaltensänderung
   trifft beide. Nichts entfernen, ohne die Aufrufe in beiden Projekten zu prüfen.
2. **Während am Tool gearbeitet wird, läuft keine Arbeitssitzung.** Kein paralleler
   ZK-Inkjet- oder Starfish-Chat, kein offenes Ghidra aus laufender Analyse. Jede
   Serveränderung erfordert ohnehin einen Neustart — mitten in einer Analysesitzung
   wäre das Ergebnis weder reproduzierbar noch der Sitzungsstand sicher.
   Für die Tests wird eine **dedizierte Ghidra-Instanz** gestartet, gegen eine Kopie des
   ZK-Inkjet-Projekts (`.rep` kopieren, nicht das Original öffnen — Lock). Sie wird nach
   dem Testlauf wieder geschlossen. Daraus folgt: **alle Tests sind Skripte, keine
   interaktiven Abfragen.** Was nicht ohne Chat wiederholbar ist, zählt nicht als Test.
   Diese Kopie wird **eingefroren** und ist die einzige, gegen die Referenzläufe laufen.
   Nicht das Binary ist das Vergleichsrisiko — es ändert sich nicht —, sondern die `.rep`:
   Renames, Kommentare und angewandte Datentypen verschieben Antwortgrößen ohne jeden
   Bezug zum Rework.
3. **Schreibende Tools behalten `dry_run=True` als Default.** `GHIDRA_MCP_ENABLE_WRITES`
   bleibt, wie es ist. Die Testsuite setzt den Wert jedoch **selbst** auf `false`, statt
   sich auf die Umgebung zu verlassen: python-dotenv sucht aus dem Worktree nach oben und
   findet die `.env` des Hauptrepos, in der `true` steht. Ein Testlauf, der nur zufällig
   nicht schreibt, ist kein Schutz.
4. **Kein neues Beschreibungsdokument.** Ergebnisse gehen in Docstrings, Tests und
   Commit-Messages. Dieses Dokument wird fortgeschrieben, nicht ergänzt.
5. **Ein Negativbefund aus einem Werkzeug ist erst dann ein Fakt, wenn die Methode als
   tauglich belegt ist.** Gilt auch beim Testen des Servers selbst: „Tool liefert nichts"
   ist kein bestandener Test.
6. **Verhältnisse, damit nicht am Falschen optimiert wird.** Referenzlauf ~46 500 Token,
   davon ~28 000 (60 %) aus zwei `search_scalars_with_context`-Aufrufen. Schema-Sockel
   7 610, einmal pro Sitzung — 16 % bei 40 Aufrufen, einstellig bei zweihundert. Die
   Trimmrunde über sieben Alt-Beschreibungen brachte 194 Token, also 0,4 %.
   **Optimiert wird an Antwortvolumen, nicht am Sockel.** Der Sockel hat einen Test als
   Geländer; er wird nicht unterboten, und die Decke ist kein Ziel. Wer sie reißt,
   begründet es und setzt sie neu.
7. **Ein Skip-Grund ist eine Behauptung.** Er unterliegt derselben Belegpflicht wie
   ein Testergebnis. „Übersprungen, weil keine Ghidra-Instanz" ist eine Aussage über
   die Umgebung — steht sie da, während Ghidra läuft, wurde nicht nur nichts geprüft,
   sondern auch noch falsch begründet, warum. Genau das war der Fall: das Gate meldete
   `no Ghidra instance`, obwohl die Instanz antwortete und lediglich `RUN_LIVE_TESTS=0`
   gesetzt war. Jede Sonde unterscheidet deshalb die Fälle einzeln — abgeschaltet,
   nicht erreichbar, keine Projektdaten, falsches Programm — und nennt den zutreffenden.
   Gilt sinngemäß für jede Meldung, die erklärt, warum etwas *nicht* getan wurde.
8. **Das strukturelle Skript lässt keinen Mengenparameter implizit.** Jeder `count`,
   `limit`, `page`, `offset`, `context_lines`, `fields`, `options`, `include_literals`,
   `fmt` und `mode` steht explizit im Aufruf, auch in den `collect`-Unterqueries. Grund:
   ein Default-Wechsel darf dort **nie** sichtbar werden — in genau dem Skript, dessen
   einzige Aufgabe es ist, die angeforderte Menge konstant zu halten, wäre er eine
   strukturelle Ersparnis, die niemand erarbeitet hat. Die Prüfung darauf ist keine
   Ermessensfrage, sondern Vollständigkeit, und liegt als Test vor
   (`bridge/tests/unit/test_structural_run_completeness.py`), nicht als Handarbeit.

---

## Stufe 0 — Messen, bevor irgendetwas angefasst wird

**Ziel:** eine Rangliste, welche Tools tatsächlich Kontext kosten. Ohne sie ist jede
Optimierung geraten.

- `collect` berechnet in seiner Aggregat-Metadata bereits eine Token-Schätzung. Dieselbe
  Schätzfunktion für *jeden* Tool-Aufruf anwenden.
- Pro Aufruf eine Zeile in ein JSONL-Log: Zeitstempel, Tool, Parameter (gekürzt),
  Ergebnisgröße in Bytes, geschätzte Token, Trefferzahl, Dauer.
- Log per Env-Variable schaltbar, Default aus.
- Einmal die Schema-Kosten bestimmen: Gesamtlänge aller 35 Tool-Beschreibungen in Token.
  Das ist der Sockelbetrag, den jede Sitzung zahlt, bevor ein einziger Aufruf passiert.

**Referenzlauf statt echter Sitzung.** Da parallel keine Arbeitssitzung läuft, kommt die
Baseline aus einem festen Skript: 30–50 Aufrufe, die eine typische Analysesitzung
nachbilden — Funktionssuche, Stringsuche mit Xrefs, Skalarsuche, Disassemblat mehrerer
Adressen, `analyze_function_complete` auf zwei bekannte Funktionen, Literalpool-Lesung
bei 0x002AFB34. Fest verdrahtete Adressen, keine Zufallsauswahl. Das ist der bessere
Maßstab: eine interaktive Sitzung ist nicht wiederholbar, dieses Skript schon.

**Das Skript protokolliert zu Beginn die Identität der Datenbank**, gegen die es läuft:
Programmname, Prüfsumme des Binaries, Zahl der Funktionen, Zahl der benutzerdefinierten
Symbole. Weicht einer dieser Werte in Stufe 7 ab, ist der Vergleich ungültig und wird
nicht ausgewertet. Das ersetzt die Annahme „die Datenbank hat sich nicht verändert"
durch eine Prüfung.

Falls ältere Sitzungslogs existieren, dürfen sie den Referenzlauf informieren, aber nicht
ersetzen.

**Abnahme:** der Referenzlauf erzeugt ein Log; daraus eine Tabelle „Token nach Tool,
absteigend" und der Schema-Sockel als Zahl. Diese Zahlen sind die Baseline für Stufe 7.

---

## Stufe 1 — Beschreibungen nachziehen

**Ziel:** Werkzeugauswahl verbessern. Reine Textarbeit, kein Verhaltensrisiko.

**Erster Schritt: die Zähldifferenz klären, bevor eine Zeile geschrieben wird.**
Der Plan nannte 27 Tools ohne Beschreibung, Stufe 0 misst 16. Die 27 stammen aus dem,
was der MCP-Client tatsächlich als Schema geliefert bekommt — dort trugen genau acht
Tools eine Beschreibung: `collect`, `disassemble_at`, `list_functions_in_range`,
`read_bytes`, `search_exports`, `search_imports`, `search_scalars`, `search_xrefs_to`.
Wenn beide Messungen stimmen, haben elf Tools einen Docstring im Code, der beim Modell
nie ankommt. Das ist schlimmer als ein fehlender Docstring, weil er beim Nachzählen als
erledigt gilt.

Zwei Prüfungen, zusammen zehn Minuten:

1. Misst `measure_schema_cost.py` die Docstrings per Introspektion oder die tatsächliche
   `tools/list`-Antwort des Servers? Nur letztere zählt — sie ist, was das Modell sieht.
   Falls Introspektion: Skript auf `tools/list` umstellen und neu messen. (Rahmen 5: eine
   Messung ist erst dann ein Fakt, wenn die Methode als tauglich belegt ist.)
2. Benutzt `tracked_tool` `functools.wraps`? Ein Wrapper ohne das löscht `__doc__` bei
   allen 35 Tools auf einen Schlag — frisch in Stufe 0 eingebaut und ein Kandidat für
   genau diese Differenz.

Erst danach die Liste der tatsächlich beschreibungslosen Tools aus `tools/list` ziehen
und abarbeiten.

Jede Beschreibung enthält:
- einen Satz, was das Tool tut,
- **wofür es nicht taugt** (die Methodengrenze, siehe Stufe 2), in *einer* Zeile,
- alle Parameter mit Wertebereich.

**Der Docstring wird in jeder Sitzung bezahlt, der `method_note` nur im Fehlerfall.**
Der ausführliche Blindflecktext mit konkreten Adressen und Aufrufbeispiel gehört deshalb
ausschließlich nach `method_notes.py`, nicht zusätzlich in den Docstring. Der Docstring
bekommt die Kurzform: „sieht keine Konstantenpool-Worte; bei 0 Treffern nennt die Antwort
den Alternativpfad." Der Synchron-Test prüft entsprechend nicht Textgleichheit, sondern
dass zu jedem Tool mit Blindfleck ein `method_note` existiert.

**Sockel-Budget.** Der Schema-Sockel ist Teil der Abnahme, nicht ein Nebeneffekt.
Baseline 5406 Token. Steigt er über etwa 8000, wird `measure_schema_cost.py` pro Tool
absteigend ausgegeben und gekürzt, bevor die Stufe als fertig gilt. Tragen drei oder vier
Tools den Zuwachs, ist das Trimmen billig; ist er gleichmäßig verteilt, war die
Dokumentation nötig und der Sockel ist der ehrliche Preis — dann wird er so benannt.

Vorrangig: `analyze_function_complete`. Die Parameter `fields`, `fmt` und `options` sind
ohne dokumentierte Werte unbenutzbar — dort steckt bereits eine Budgetsteuerung
(`max_result_tokens`), die deshalb nie greift.

Für die Suchtools Stufe 1 und Stufe 2 in einem Zug erledigen — der Methodenhinweis und
die Beschreibung sind derselbe Text.

**Abnahme:** in der `tools/list`-Antwort des laufenden Servers kein Tool ohne
Beschreibung und kein Parameter ohne dokumentierten Wertebereich; `fields`-Liste von
`analyze_function_complete` vollständig aufgeführt. Nicht per Introspektion geprüft.

---

## Stufe 2 — Methodenhinweis bei Negativbefunden

**Ziel:** die teuerste dokumentierte Fehlerklasse des Projekts unmöglich machen.

Jedes Suchtool liefert bei leerem Ergebnis zusätzlich ein Feld `method_note`, das
benennt, was dieser Suchmodus konstruktionsbedingt **nicht** sieht, und den
Alternativpfad nennt.

**Korrektur an der Auslösebedingung (bei der Umsetzung gefunden):** `total == 0` ist das
falsche Kriterium. Bei kleinem `limit` paginieren diese Suchen per Cursor und melden
`total: None` — die ursprüngliche Regel hätte genau die Leerergebnisse übersprungen, die
eine echte Sitzung produziert. Maßgeblich ist die **Leere der Ergebnisliste**, wenn
`total` unbekannt ist. Angehängt wird in den Feature-Funktionen, nicht in den
Tool-Wrappern, und vor dem Cache-Write — sonst ist ein Cache-Treffer eine stille Ausnahme.

**Korrektur an der Tabelle:** „Bytesuche" gab es in meiner Fassung zweimal als
Alternativpfad. **Diesen Endpunkt gibt es nicht** — weder in der Bridge noch im
Java-Plugin. Ein Hinweis auf eine fehlende Fähigkeit wiederholt exakt den Fehler, den er
verhindern soll. Alternativpfade dürfen nur auf Tools zeigen, die am laufenden Programm
verifiziert wurden.

| Tool | Blinder Fleck | Alternativpfad |
|---|---|---|
| `search_scalars`, `search_scalars_with_context` | Konstantenpool-Worte, PC-relative Loads | `find_in_function` mit `ldr` → Pooladresse aus dem Operanden → `read_words` |
| `search_functions` | nur Namensmuster, keine Semantik | `search_strings` + `string_xrefs_compact` |
| `search_xrefs_to` | Referenzen, die Ghidra nicht als solche erkannt hat | `read_words` über den Bereich, in dem das Adresswort erwartet wird |

**Regressionstest (Pflicht), gegen `ZK-INKJET-NANO-APP.bin`:**
1. `search_scalars("0xB1008000")` → 0 Treffer **und** vorhandener `method_note`.
2. Der im `method_note` genannte Alternativpfad findet `0x002AFB4C` (USBD_BA) und
   `0x002AFB40` (USBD_BA+0x704).

Test 1 allein gilt nicht als bestanden. Genau diese Verwechslung — leeres Ergebnis als
Aussage über die Firmware gelesen — hat den USB-Pfad sieben Monate blockiert.

**Abnahme:** beide Teilschritte grün, als automatisierter Test hinterlegt.

---

## Stufe 2b — Den Schätzer reparieren

**Ziel:** das Budget misst, was es begrenzen soll. Neu aufgenommen nach dem Befund aus
Stufe 0.

`est_tokens` zählt nur Strings; über den Referenzlauf liegt der Faktor zu `Bytes/4` bei
2,3. Damit ist `max_result_tokens` in `collect` und `analyze_function_complete` keine
wirksame Grenze, sondern eine, die um mehr als das Doppelte danebenliegt. Das trifft
Stufe 6 direkt: „`collect` als einziger Lesepfad, damit das `result_budget` zwangsläufig
greift" nützt nichts, solange das Budget die falsche Größe misst. Deshalb vor Stufe 3
und zwingend vor Stufe 6.

- Zahlen, Bytefolgen, Adressen und Strukturschlüssel mitzählen. Einfachste taugliche
  Näherung: serialisierte Länge / 4 über die gesamte Antwort, nicht nur über
  String-Felder.
- Ein Testfall pro Antworttyp, der Schätzung gegen tatsächliche serialisierte Länge
  hält. `read_words` ist der Grenzfall (bisher 4 Token für 292 Bytes).
- `strict`-Modus einmal wirklich auslösen: ein Aufruf mit knappem `max_result_tokens`
  muss `RESULT_TOO_LARGE` liefern. Bisher ist unbelegt, dass der Pfad je erreicht wurde.

**Abnahme:** derselbe Referenzlauf; das Verhältnis `est_tokens` zu `Bytes/4` liegt im
Mittel bei 0,9–1,1, kein einzelner Tooltyp unter 0,7. Der `strict`-Test ist grün.

**Nachtrag: diese Abnahme war unfalsifizierbar.** Sobald der Schätzer serialisiert, *muss*
das Verhältnis 1,00 sein — die Bedingung prüft die Reparatur nicht, sie bestätigt nur,
dass sie stattgefunden hat. Was tatsächlich trägt, sind die Tests in
`test_token_estimator.py` (acht Antwortformen gegen die tatsächliche serialisierte Länge)
und die erstmalige Auslösung von `strict`.

Die naheliegende Anschlussfrage — gilt Länge/4 für dichtes JSON mit Hex-Adressen, oder
eher Länge/2,5 bis /3? — wird **ausdrücklich nicht verfolgt.** Sie entscheidet nur, ob
eine Budget-Schwelle um ein Viertel danebenliegt, die in der Praxis kaum je gezogen wird.
Stattdessen ein Satz im Docstring: *geschätzt als serialisierte Länge / 4, bei dichtem
JSON systematisch etwas zu niedrig.*

**Und: `est_tokens` ist ab hier eine reine Ableitung aus Bytes.** Zwei Spalten, eine
Information. Berichte führen Bytes; `est_tokens` allenfalls als Divisionsergebnis, nie
als zweiter Beleg.

**Folge für die Berichterstattung:** `est_tokens` ist zwischen Stufe 0 und Stufe 7 nicht
mehr vergleichbar. Leitgröße für den Vorher-Nachher-Vergleich sind **Antwort-Bytes**.
`est_tokens` bleibt als zweite Spalte stehen, aber es wird nicht darauf optimiert.

---

## Stufe 3 — Defaults senken, Trunkierung sichtbar machen

**Ziel:** Antwortgrößen, die nicht mehr überraschen.

Aktuelle Defaults sind Kontextbomben: `search_scalars_with_context` limit 100 bei
context_lines 4 (bis ~900 Zeilen Disassemblat pro Antwort), `list_functions_in_range`
limit 200, `search_functions` limit 100, `find_in_function` limit 50 × 7 Zeilen.

- Defaults auf 10–20 senken. Der hohe Wert bleibt als expliziter Parameter erreichbar.
- Jede paginierte Antwort macht Trunkierung sichtbar. **Nicht über `total`** — bei
  Cursor-Pagination ist `total` konstruktionsbedingt unbekannt (`None`), das hat Stufe 2
  gezeigt. Maßgeblich sind `truncated` (bool) und ein Weiterlese-Signal (Cursor vorhanden
  ja/nein). `total` nur dort führen, wo es tatsächlich bekannt ist, und sonst weglassen —
  **niemals schätzen**, sonst wird die Trunkierung wieder unsichtbar. Was fehlt, muss
  sichtbar fehlen, sonst entsteht Stufe 2 an anderer Stelle neu.
- Ein Ausgabemodus `fmt="text"` für Disassemblat-Listen. JSON zahlt Anführungszeichen,
  Klammern und wiederholte Schlüssel pro Zeile.
- Der Nebenbefund aus Stufe 0 bekommt hier sein Zuhause: `search_imports` scheitert an
  `0xEXTERNAL:00000001` gegen `^0x[0-9a-fA-F]+$`. Schema erweitern, Testfall dazu. Ein
  Tool, das auf dem Hauptprogramm reproduzierbar fehlschlägt, ist kein Nebenbefund.

**Abnahme:** Vergleich am selben Aufruf vor/nach, Ersparnis in Antwort-Bytes
dokumentiert. `search_imports` läuft im Referenzlauf durch.

---

## Stufe 4 — `disassemble_batch` bekommt einen Filter

**Ziel:** den teuersten Aufruf des Servers zum billigsten machen.

`find_in_function` filtert serverseitig, `disassemble_batch` nicht — 20 Adressen × 16
Instruktionen = 320 Zeilen, von denen typischerweise drei gebraucht werden. Dieselben
Parameter übernehmen: `query`, `regex`, `case_sensitive`, `context_lines`. Ohne `query`
bleibt das Verhalten unverändert.

**Abnahme:** ein realer Fall aus dem Projekt — etwa „alle `ldr`-Pool-Zugriffe in diesen
Funktionen" — vorher/nachher in Token gemessen.

---

## Stufe 5 — Mutationen exportierbar machen

**Ziel:** die Ausbeute einer Sitzung verlässt Ghidra.

Renames und Kommentare landen in der `.rep` und in keinem versionierten Artefakt.
`check_dirty_state` weiß, *dass* etwas offen ist, nicht *was*.

Neues Tool `list_mutations`: alle Umbenennungen, Kommentare und Datentyp-Änderungen seit
dem letzten `save_program`, mit Adresse, altem und neuem Wert. Ausgabe so, dass sie
direkt in eine Commit-Message oder eine TRUTH-Zeile passt.

**Abnahme (korrigiert):** nach drei probeweisen Renames im Dry-Run-Modus listet das Tool
genau diese drei — **jeweils mit aufgelöstem altem und neuem Wert**.

Die ursprüngliche Fassung prüfte nur die Anzahl. Der erste Abnahmelauf hätte sie bestanden
und war wertlos: alle drei Einträge lasen `? -> neuer_name`, weil der alte Name mit
`meta.get("name")` aus einer Prosa-Antwort geholt wurde, die kein solches Feld hat. Die
Hälfte dessen, wofür das Journal da ist — alter *und* neuer Wert —, war leer, und der Test
sagte nichts. Eine Abnahme, die die Anzahl zählt und den Inhalt nicht ansieht, ist eine
Zählung, keine Abnahme.

**Zusätzlich hier, aus Stufe 6 hierher verschoben: die `strict`-Asymmetrie.** Eine
Budgetverletzung auf Query-Ebene liefert ein fehlgeschlagenes Teilergebnis und lässt den
Rest des Batches stehen; eine auf Request-Ebene reißt den ganzen Batch. Richtig ist die
Query-Variante — wer einen Batch schickt, will die übrigen zwölf Ergebnisse. Also
Request-Ebene ebenfalls auf partiell, mit einem Feld, das nennt, welche Queries am Budget
gefallen sind. Dasselbe Prinzip wie bei `auto_trim`: ein weggelassenes Ergebnis darf nie
wie ein geliefertes aussehen. Korrektheitsfrage, nicht Budgetfrage.

---

## Stufe 6 — Oberfläche halbieren

**Status: entschieden — wird nicht gebaut.** (2026-08-20)

Zwei Argumente trugen diese Stufe, beide halten nicht mehr.

**Das Budgetargument ist seit Rahmen 6 hinfällig.** Der Schema-Sockel liegt bei
rund 8 200 Token, einmal pro Sitzung — sechzehn Prozent bei vierzig Aufrufen,
einstellig bei zweihundert. Stufe 6 spart davon die Hülle, also wenige Prozent
von wenigen Prozent. Zum Vergleich: der `disassemble_batch`-Filter aus Stufe 4
spart 85 % an einem Aufruf, der pro Verwendung bezahlt wird.

**Das Ambiguitätsargument ist real, aber unbelegt.** Dreizehn Leseoperationen
existieren doppelt, eigenständig und als `op` in `collect`, ohne Kriterium,
welches zu wählen ist. Über sechs Stufen Arbeit an genau dieser Oberfläche hat
sich daraus **kein einziges Mal** eine Fehlwahl ergeben. Ein Umbau ohne belegtes
Problem — an der einzigen Stelle, die Aufrufe in zwei Projekten brechen kann — ist
das schlechteste Verhältnis von Risiko zu Nachweis in diesem ganzen Rework.

**Bleibt als Option notiert.** Tritt eine echte Fehlwahl auf — ein Aufruf, der das
falsche der beiden Werkzeuge wählt und dadurch schlechter fährt —, ist das der
Anlass, und dann liegt die Begründung vor, die heute fehlt.

Die Entscheidung zu `jt_scan` / `jt_slot_check` / `jt_slot_process` entfällt damit
ebenfalls; sie bleiben, wo sie sind.

**Die `strict`-Asymmetrie wandert nach Stufe 5.** Sie war hier nur einquartiert,
weil `collect` ohnehin angefasst worden wäre. Sie ist eine Korrektheitsfrage —
eine Budgetverletzung auf Request-Ebene reißt den ganzen Batch, eine auf
Query-Ebene nicht — und keine Budgetfrage, also hängt sie nicht an dieser
Entscheidung.

---

## Stufe 7 — Nachmessen

Derselbe Referenzlauf wie in Stufe 0, unverändert, dasselbe Logging, Vergleich der
Zahlen. Wurde das Skript zwischendurch angepasst, ist der Vergleich wertlos — dann
zuerst die alte Fassung nochmals laufen lassen. Ohne diesen Schritt ist der Rework eine
Behauptung.

**Leitgröße sind Antwort-Bytes, nicht `est_tokens`** — der Schätzer wird in Stufe 2b
verändert und ist über die Stufen hinweg nicht vergleichbar.

**Byte-Baselines, fortgeschrieben.** Stufe 0: 184 441. Ab Stufe 2: **186 066** (+0,9 %,
ausschließlich `method_note`-Text auf leeren Ergebnissen, davon `search_functions` +924
und `search_scalars` +701). Der Aufschlag gehört zu Stufe 2 und wird beim Nachmessen
getrennt ausgewiesen — sonst schreibt sich eine spätere Stufe die Einsparung gut, die
diese hier gekostet hat. Gleiches gilt für jede weitere Stufe, die Bytes hinzufügt: neue
Baseline nennen, Ursache benennen, nicht verrechnen.

**Der Bericht trennt zwei Blöcke.** Sonst schmeichelt sich der Lauf selbst: die beiden
`search_scalars_with_context`-Aufrufe der Baseline laufen auf Default-limit 100, das
Stufe 3 senkt. Ein Nachher-Lauf zeigt dann eine gewaltige Ersparnis, die überwiegend
Parameteränderung ist und nicht mehr Effizienz pro gelieferter Information.

- **Default-Effekt** — Aufrufe ohne explizite Mengenparameter. Sie messen, was eine
  unbedarfte Sitzung spart. Ehrlich zu benennen als das, was es ist.
- **Strukturelle Ersparnis** — Aufrufe mit fest gesetzten Parametern, also gleiche
  angeforderte Menge vorher wie nachher. Hier zeigt sich `fmt="text"`, der
  `disassemble_batch`-Filter, das schlankere Envelope.

**Abnahme:** beide Blöcke getrennt ausgewiesen, aufgeschlüsselt nach Tool, plus der
Schema-Sockel gegen die 5406 Token der Baseline. Was sich nicht verbessert hat, wird
benannt und nicht wegerklärt.

---

## Stufe 8 — Die Naht zwischen Plugin und Bridge

**Ziel:** die Bridge rekonstruiert nicht mehr per Regex, was Ghidra bereits weiß, und
bietet nichts an, was das Plugin nicht kann. Aufgenommen nach dem Review vom 2026-10-08.

**Befund, der diese Stufe trägt.** 32 der 51 Plugin-Routen antworten nur mit Text,
17 mit JSON, eine gemischt, eine unklar (Zählung über die `register*Handler`-Aufrufe in
`GhidraMCPPlugin.java`). Bei den meisten Textrouten zerlegt `client.py` ein, zwei
Felder — harmlos. Teuer ist eine Stelle: `/disassembleAt` und `/disassemble_function`
liefern `adresse: bytes instr.toString()`. Sieben Feature-Module verarbeiten diesen Text
weiter (`disasm`, `batch_ops`, `mmio`, `analyze`, `search_function`, `strings`,
`functions`); `mmio`, `analyze` und `strings` lesen daraus per Regex Mnemonic,
Operanden, Calls, Call-Ziele, Branches, Pool-Worte und MMIO-Basen zurück. Das Commit-Log seit Stufe 5 ist überwiegend Reparatur an
genau dieser Naht: `MOV`-Basen nicht aufgelöst, Pool-Worte als Strings, Prosa-Parse
abgesichert, Thunks verschwiegen. Jede neue Befehlsform ist dort ein neuer Fehler.

Die Teilstufen sind nach Risiko geordnet, nicht nach Nutzen. Jede ist einzeln
abnehmbar und wird einzeln committet. Jede außer 8b braucht einen Plugin-Rebuild.

### 8a — Plugin nur auf Loopback

`HttpServer.create(new InetSocketAddress(port), 0)` bindet auf alle Interfaces, ohne
Authentifizierung. Der Schreibschutz (`dry_run`, `GHIDRA_MCP_ENABLE_WRITES`) sitzt nur in
der Bridge; `/renameFunction`, `/renameData`, `/set_function_prototype` und die
Datentyp-Routen sind am Plugin direkt erreichbar. Auf dem Laptop in einem fremden Netz
heißt das: jeder im Segment liest und ändert das Projekt.

- Bind auf `InetAddress.getLoopbackAddress()`.
- Eine Plugin-Option für die Bind-Adresse, Default Loopback. Wer sie ändert, tut es
  bewusst; das Plugin loggt dann beim Start eine Warnung mit der Adresse.

**Abnahme:** nach Rebuild zeigt `ss -ltnp` den Port nur auf `127.0.0.1`; ein Aufruf über
die LAN-Adresse des Rechners wird abgewiesen, einer über `127.0.0.1` beantwortet. Beides
als Skript, nicht als Augenschein.

### 8b — Keine Tools ohne Gegenstück im Plugin

`write_bytes` und `project_rebase` sind MCP-Tools und in `docs/api.md` dokumentiert. Die
Bridge ruft dafür `startTransaction`, `commitTransaction`, `rollbackTransaction`,
`writeBytes`, `rebuildCodeUnits` und `rebaseProgram` auf — **keiner dieser Endpunkte
existiert im Java-Quellcode.** Beide Tools scheitern am ersten Schritt; die Tests sind
grün, weil `bridge/tests/contract/conftest.py` und die Unit-Tests die Endpunkte als Stub
nachbilden. Die Tests belegen das Verhalten des Stubs, nicht das des Plugins. Das ist
derselbe Fehler wie die „Bytesuche" in Stufe 2, nur im Code statt im Hinweistext.

- **Erst ein Geländer, dann die Entscheidung:** ein Unit-Test, der die registrierten
  Routen aus `GhidraMCPPlugin.java` extrahiert und prüft, dass jeder Pfad und jeder Alias
  in `ENDPOINT`-Tabellen von `client.py` dort vorkommt. Er muss vor jeder Änderung rot
  werden — mit genau den sechs Namen oben. Wird er das nicht, taugt die Extraktion nicht
  (Rahmen 5).
- **Dann entscheiden: entfernen oder bauen.** Empfehlung: entfernen. Beide Tools haben
  nie funktioniert; in keinem der beiden Projekte kann ein Aufruf brechen, der vorher
  ging (Rahmen 1 trotzdem prüfen, Aufrufe dort suchen und benennen). Byte-Patches und
  Rebase sind seltene, folgenreiche Eingriffe, die in der Ghidra-Oberfläche besser
  aufgehoben sind. Wer bauen will, baut sie mit Plugin-seitiger Transaktion, nicht mit
  einem Transaktionsprotokoll über HTTP.
- Danach dieselbe Prüfung über alle übrigen Stub-Endpunkte: jeder Stub, der eine Route
  nachbildet, die das Plugin nicht hat, fliegt raus oder bekommt einen Kommentar, warum
  er bleibt.

**Abnahme:** der Routen-Test ist grün und war vorher nachweislich rot; `tools/list` des
laufenden Servers enthält kein Tool, dessen Plugin-Pfad fehlt.

### 8c — Disassemblat als Struktur

`/disassembleAt` und `/disassemble_function` bekommen `fmt=json`. Der Textmodus bleibt
Default, bis die Bridge umgestellt ist — beide Projekte laufen gegen dasselbe Plugin
(Rahmen 1), ein Plugin-Rebuild darf keinen Bridge-Stand brechen.

Pro Instruktion, alles aus der Ghidra-API statt aus `toString()`:
- `address`, `bytes`, `mnemonic`, `text` (die bisherige Darstellung, für `fmt="text"`
  der Bridge),
- `flow`: Call, bedingter/unbedingter Sprung, Return, Fallthrough,
- `operands`: pro Operand Register, Skalare und Typ,
- `refs`: Referenzen ab dieser Instruktion mit Zieladresse, Typ, und ob das Ziel im
  Speicherbild liegt,
- bei PC-relativen Loads: Pooladresse **und** das geladene Wort.

Danach die Regex-Pfade in den sieben Modulen durch Feldzugriffe ersetzen, Modul für
Modul, jeweils mit eigenem Commit.

**Offene Frage, vor dem Umbau von `mmio.py` zu klären:** legt Ghidras
Konstantenpropagation für ARM eine Referenz an, wenn das Ziel außerhalb des
Speicherbilds liegt? Im ZK-Inkjet-Programm ist nur `flash` @0x00200000 gemappt; die
MMIO-Bereiche nicht. Falls nein, liefert `refs` für MMIO nichts, und `mmio.py` behält
die Basis-Auflösung aus `operands` — aber aus Skalaren, nicht aus Text. Eine
Speicherkarte mit MMIO-Blöcken wäre die saubere Lösung, ändert aber die `.rep` und damit
die eingefrorene Referenzkopie (Rahmen 2); falls gewünscht, als eigene Entscheidung mit
neuer Baseline, nicht nebenbei. Die Antwort wird am laufenden Programm ermittelt, an
einer Funktion mit bekanntem `mov rX,#0xb…`-Zugriff, nicht aus Dokumentation.

**Abnahme:**
1. Der Stufe-2-Regressionstest findet `0x002AFB4C` und `0x002AFB40` weiterhin.
2. `mmio_annotate_compact` liefert an den Funktionen aus dem Referenzlauf dieselbe Menge
   an (Instruktionsadresse, Registeradresse) wie vorher. Jede Abweichung ist entweder
   eine belegte Korrektur oder ein Fehler — es gibt keine dritte Kategorie.
3. In `mmio.py`, `analyze.py` und `strings.py` bleibt kein Regex, der Operandentext zerlegt. Was
   bleibt, steht mit Begründung im Docstring.
4. Referenzlauf: Antwort-Bytes werden ausgewiesen, aber nicht optimiert. Die Stufe zielt
   auf Korrektheit; wächst das Volumen, wird es benannt (Stufe 7, Fortschreibung der
   Baseline).

### 8d — `/functionsInRange` als JSON

Das Eigenformat `name @ addr size span=… thunk=… chunks=…` wird durch JSON ersetzt,
gleiche Felder. Kleinkram nach 8c, aber dasselbe Prinzip: ein Format, das nur durch
Zerlegen lesbar ist, hat beim nächsten Feld wieder einen Parserfehler.

**Abnahme:** `list_functions_in_range` liefert am Referenzlauf identische Einträge;
`FUNC-CHUNKS-THUNKS` bleibt verifiziert (Thunk-Ziel, Chunks, Spanne).

**Nicht Teil dieser Stufe:** die übrigen Textrouten (`/decompile*`, `/read_cstring`,
`/get_function_by_address` usw.). Dort zerlegt die Bridge kaum etwas; ein Umbau hätte
kein belegtes Problem (Begründung wie Stufe 6). Ebenso nicht: ein Umstieg auf PyGhidra
statt HTTP. Er würde die Naht ganz beseitigen, ist aber ein Neubau, kein Rework — als
Option notiert, falls nach 8c weitere Klassen von Nahtfehlern auftreten.

---

# Ergebnisse

## Stufe 0 — Baseline (2026-08-20, Commit `cbca24d`)

Gemessen gegen die laufende Ghidra-Instanz mit `ZK-INKJET-NANO-APP.bin.orig`
(Kopie, lesend). Reproduzierbar mit:

    python scripts/reference_run.py --usage-log baseline/reference_run.jsonl
    python scripts/usage_report.py baseline/reference_run.jsonl
    python scripts/measure_schema_cost.py

**Schema-Sockel: 5406 Token über 35 Tools.** Das zahlt jede Sitzung, bevor ein
Aufruf passiert. 16 Tools ohne Beschreibung (nicht 27 — die Zahl im Plan war
veraltet). `collect` allein: 1239 Token, also 23 % des Sockels.

**Referenzlauf: 40 Aufrufe, 184 441 Bytes Antwort.**

| Tool | Aufrufe | est_tokens | Bytes | Bytes/4 |
|---|---:|---:|---:|---:|
| search_scalars_with_context | 2 | 11773 | 111662 | 27915 |
| find_in_function | 2 | 3038 | 20013 | 5003 |
| search_scalars | 3 | 1306 | 14451 | 3612 |
| analyze_function_complete | 2 | 1702 | 11631 | 2907 |
| disassemble_batch | 1 | 547 | 5035 | 1258 |
| disassemble_at | 4 | 536 | 5026 | 1256 |
| collect | 2 | 284 | 3934 | 983 |
| search_strings | 3 | 395 | 3537 | 884 |
| string_xrefs_compact | 1 | 250 | 1833 | 458 |
| list_functions_in_range | 2 | 111 | 1431 | 357 |
| search_functions | 5 | 72 | 1395 | 348 |
| Rest (11 Tools) | 12 | 466 | 4493 | 1123 |
| **Summe** | **40** | **20424** | **184441** | **46101** |

Zwei Token-Spalten, absichtlich:

- `est_tokens` ist die vorhandene Schätzfunktion (die, die das `collect`-Budget
  steuert). Sie zählt **nur Strings**. Bei `read_words` meldet sie 4 Token für
  292 Bytes Antwort — Zahlen sind für sie unsichtbar.
- `Bytes/4` ist die ehrliche Obergrenze.

Der Faktor zwischen beiden ist im Mittel 2,3. Das heißt: das `max_result_tokens`-
Budget in `collect` und `analyze_function_complete` unterschätzt systematisch,
was es begrenzen soll. Nicht in Stufe 0 geändert (Stufe 0 misst, sie baut nicht
um), aber es ist die Erklärung dafür, warum das Budget in der Praxis nie greift —
zusätzlich zu dem in Stufe 1 genannten Grund, dass der Parameter undokumentiert ist.

**Bestätigt:** `search_scalars_with_context` ist mit 61 % aller Antwort-Bytes aus
zwei Aufrufen der teuerste Aufruf des Servers. Die Vermutung aus Stufe 3 stimmt.

**Nebenbefund (nicht behoben, weil in keiner Stufe):** `search_imports` schlägt
auf diesem Programm reproduzierbar mit `INVALID_REQUEST` fehl — Ghidra liefert
`0xEXTERNAL:00000001` als Adresse, das Schema erlaubt nur `^0x[0-9a-fA-F]+$`.
Der Aufruf bleibt im Referenzlauf, damit die Zahl ehrlich bleibt.

---

## Stufe 0 — Nachtrag (Commit `fae6309`)

Rahmenbedingung 2 und 3 nachgezogen.

**Fingerabdruck der Datenbank.** `reference_run.py` protokolliert vor dem ersten
Aufruf Programmname, SHA-256 des Binaries, Funktionszahl und Zahl der nicht
default-benannten Funktionen — als erste Zeile des Logs, damit jedes Log die
Identität dessen trägt, was es gemessen hat. `--expect-fingerprint` verweigert
den Lauf bei Abweichung (Exit 2), statt still unvergleichbare Zahlen zu
produzieren.

    ZK-INKJET-NANO-APP.bin.orig
    sha256 3be9028b01c0007aab9192877341918a0bc155beef55ac17e7e8f3bcc95151ea
    1266 Funktionen, davon 24 benutzerbenannt

Der Fingerabdruck spricht direkt mit dem Ghidra-Plugin, nicht über die Bridge —
er kostet also nichts in dem Log, das er beschriftet.

**Schreibflags.** Die Testsuite setzt `GHIDRA_MCP_ENABLE_WRITES=false` jetzt
selbst (`bridge/tests/conftest.py`), vor dem ersten Import. Kein Env-Var mehr
auf der Kommandozeile nötig.

---

## Stufe 1 — Beschreibungen (Commit `a7867cb`)

### Die Zähldifferenz: 16, nicht 27

Beide im Plan vermuteten Ursachen sind ausgeschlossen, und zwar durch drei
unabhängige Messungen, die alle dasselbe sagen:

1. **`measure_schema_cost.py` misst jetzt die echte `tools/list`-Antwort** über
   stdio (`--source both` stellt beide Sichten nebeneinander). Introspektion und
   Draht stimmen exakt überein: 35 Tools, 5406 Token, 16 ohne Beschreibung.
2. **`tracked_tool` benutzt `functools.wraps`** — alle drei Wrapper tun das.
   Es geht kein Docstring verloren.
3. **Der laufende Server, mit dem der Client tatsächlich spricht**, liefert für
   `read_words`, `check_dirty_state`, `goto_address`, `save_program` und
   `select_program` Beschreibungen aus, für `analyze_function_complete`,
   `strings_compact` und `project_info` keine. Genau die 19/16-Teilung.

Die Lesart „genau acht dokumentiert" ist gegen keine der drei Messungen
reproduzierbar. Diese Stufe arbeitet deshalb gegen die gemessene Liste.

### Korrektur am Plan: „Bytesuche" gibt es nicht

Der Alternativpfad für `search_scalars` und `search_xrefs_to` war im Plan zweimal
„Bytesuche". **Diesen Endpunkt gibt es nicht** — weder in der Bridge noch im
Java-Plugin (geprüft gegen die Endpunktliste beider). Ein Methodenhinweis, der auf
eine nicht vorhandene Fähigkeit zeigt, würde genau den Fehler wiederholen, den er
verhindern soll (Rahmen 5).

Die Hinweise zeigen stattdessen auf das, was nachweislich trägt — gegen die
laufende Firmware verifiziert:

    search_scalars("0xB1008000")   -> total 0
    read_words(0x002AFB34, 10)     -> 0x002AFB4C = 0xB1008000   (USBD_BA)
                                      0x002AFB40 = 0xB1008704   (USBD_BA+0x704)

Und wie man den Pool überhaupt findet: `find_in_function` mit `ldr` zeigt ihn im
Operanden (`ldr r1,[0x2afb34]`). Damit ist der Stufe-2-Regressionstest inhaltlich
schon belegt; Stufe 2 hängt ihn nur noch an die Antwort.

### Ergebnis

`bridge/features/method_notes.py` hält die Blindfleck-Texte **einmal**. Stufe 1
zitiert sie in den Beschreibungen, Stufe 2 hängt sie an leere Antworten. Ein Test
hält beide Kopien synchron.

Geschrieben: 16 fehlende Beschreibungen plus Neufassung der sieben Einzeiler ohne
Wertebereiche. Alle Wertebereiche aus dem Code gelesen, nicht angenommen
(`read_bytes` klemmt bei 4096, `disassemble_at` bei 128, die paginierten Suchen
bei `GHIDRA_MCP_MAX_ITEMS_PER_BATCH`).

**Abnahme, am Draht gemessen:** 35 Tools, 0 ohne Beschreibung, 0 Parameter ohne
Dokumentation — erzwungen durch `bridge/tests/unit/test_tool_descriptions.py`.
`analyze_function_complete`: alle sieben `fields`-Werte, `fmt` nur `json`,
`max_result_tokens` mit Einheit und Null-Fall, jeder `options`-Schlüssel mit
Grenzen und Default.

**Preis: der Schema-Sockel steigt von 5406 auf 11334 Token.** Das ist die Rechnung
dieser Stufe und wird nicht kaschiert — Stufe 6 senkt die Oberfläche wieder.
Antwort-Bytes unverändert bei 184 441 über den 40-Aufruf-Referenzlauf; diese Stufe
fasst nur Text an.

---

## Stufe 1 — Sockel getrimmt (Commit `95b55fa`)

Rangliste zeigte: der Zuwachs war **gleichmäßig verteilt** über die 26
neugeschriebenen Tools, keine drei Ausreißer zum Kappen. Also knappere Hausform
überall plus die Aufteilung aus der Plan-Ergänzung.

| Tool | Baseline | aufgebläht | getrimmt |
|---|---:|---:|---:|
| collect | 1239 | 1239 | 705 |
| analyze_function_complete | 141 | 773 | 467 |
| jt_slot_process | 146 | 437 | 368 |
| datatypes_create | 104 | 467 | 312 |
| search_functions | 298 | 496 | 301 |
| find_in_function | 457 | 457 | 297 |
| **Summe (35 Tools)** | **5406** | **11334** | **7804** |

Der lange Blindflecktext mit Adressen und Aufrufbeispiel steht jetzt
ausschließlich in `method_notes.py`; `SHORT_FORM` liefert die Einzeiler für die
Docstrings. Der Synchron-Test prüft Existenz und Zusammengehörigkeit — und
zusätzlich, dass `0x002AFB4C` und `read_words` *nicht* im Docstring stehen, damit
der Text nicht zurückwandert. `SCHEMA_BASE_CEILING = 8000` als Test.

Zusätzlich mitgetrimmt, obwohl nicht Teil der Stufe: `collect` und
`find_in_function` trugen zusammen 15 % des Sockels und hatten 17 fast identische
`Example:`-Zeilen. `collect`s vollständige `op`-Liste bleibt — Stufe 6 hängt daran.
Ohne diese beiden wäre der Sockel bei 8498 geblieben.

Nicht angefasst: sieben Alt-Beschreibungen (`set_comment` 285, `rename_function`
224, `save_program` 164, `disassemble_batch` 159, `select_program` 152,
`check_dirty_state` 122, `goto_address` 116 = 1222 Token). Reserve, falls Stufe 6
das Ziel verfehlt.

---

## Stufe 2 — Methodenhinweis (Commit `ea3f241`)

`method_note` hängt bei leerem Ergebnis an `search_scalars`,
`search_scalars_with_context`, `search_functions`, `search_xrefs_to` und
`search_strings`.

Angehängt in den **Feature-Funktionen**, nicht in den Tool-Wrappern — damit
tragen MCP-Tools, HTTP-Routen und `collect` den Hinweis ohne drei Kopien der
Entscheidung. Vor dem Cache-Write, damit ein Cache-Treffer keine stille Ausnahme
ist. Alle fünf Schemata haben `additionalProperties: false` und wurden erweitert,
OpenAPI-Snapshot neu erzeugt.

### Korrektur an der Regel: `total == 0` reicht nicht

Bei kleinem `limit` paginieren diese Suchen per Cursor und melden `total: None`.
Die Regel „anhängen wenn `total == 0`" hätte genau die cursor-paginierten
Leerergebnisse übersprungen — also die, die eine echte Sitzung trifft. Jetzt
entscheidet die Leere der Ergebnisliste, wenn `total` unbekannt ist. Mit Test.

### Regressionstest (`bridge/tests/live/`)

    Schritt 1  search_scalars("0xB1008000") -> total 0, method_note vorhanden,
               Payload validiert weiter gegen search_scalars.v1.json
    Schritt 2  der im Hinweis genannte Pfad, ausgeführt:
               find_in_function(0x002AF9C0, 'ldr') -> Pool-Adresse aus dem
                 Operanden gelesen, nicht angenommen: 0x002AFB34
               read_words(0x002AFB34, 10)          -> 0x002AFB4C = 0xB1008000
                                                      0x002AFB40 = 0xB1008704

**Schritt 1 allein kann die Suite nicht bestehen:** `test_step_two_is_not_optional`
bindet das leere Ergebnis an den funktionierenden Pfad. Ein Hinweis, der plausibel
klingt und ins Leere führt, fällt durch.

Die Live-Tests überspringen sich ohne Ghidra — und **verweigern** statt falsch zu
bestehen, wenn die Instanz ein Binary mit anderer SHA-256 bedient.

### Preis, benannt statt wegerklärt

Antwort-Bytes im Referenzlauf **184 441 → 186 066, +0,9 %**. Alles davon sind
Hinweise auf leeren Ergebnissen (`search_scalars` +701, `search_functions` +924).
Eine leere Antwort kostet jetzt ein paar hundert Bytes mehr. Der Fehler, den sie
verhindert, hat sieben Monate gekostet.

**Folge für Stufe 7:** die Baseline für Antwort-Bytes ist ab hier 186 066, nicht
184 441. Der Aufschlag gehört zu Stufe 2 und wird beim Nachmessen getrennt
ausgewiesen.

Sockel unverändert 7804. 369 Tests grün, 10 übersprungen.

---

## Stufe 1 — letzte sieben (Commit `ec221c8`)

Sockel **7804 → 7610**, Kopffreiheit bis zur Decke 196 → 390.

| Tool | vorher | nachher | Δ |
|---|---:|---:|---:|
| set_comment | 285 | 214 | −71 |
| rename_function | 224 | 145 | −79 |
| save_program | 164 | 129 | −35 |
| check_dirty_state | 122 | 79 | −43 |
| goto_address | 116 | 106 | −10 |
| disassemble_batch | 159 | **180** | **+21** |
| select_program | 152 | **175** | **+23** |
| zusammen | 1222 | 1028 | −194 |

Zwei sind gestiegen, beides fehlende Information statt überflüssiger Worte:
`disassemble_batch` nennt jetzt seine Batch-Decke und den Fall, den Stufe 4
behebt; `select_program` nennt `GHIDRA_BRIDGE_PROGRAM_SWITCH_POLICY`.

Schätzung für die Kopffreiheit: `fmt` auf den Disassemblat-Listen ~120 Token,
die vier Filterparameter an `disassemble_batch` ~115. 390 reicht, aber nicht üppig.

---

## Stufe 2b — Schätzer repariert (Commit `2eb4280`)

`estimate_tokens` serialisiert jetzt die Antwort und teilt durch vier.

| Tool | Verhältnis vorher | nachher |
|---|---:|---:|
| read_words | 0.05 | 1.00 |
| strings_compact | 0.00 | 1.00 |
| search_functions | 0.21 | 1.00 |
| search_xrefs_to | 0.27 | 1.00 |
| collect | 0.29 | 1.00 |
| **Mittel** | **0.44** | **1.00** |

**Das 1.00 ist tautologisch** und steht im Bericht auch so. Der Schätzer wurde
darauf umgestellt, die serialisierte Antwort zu messen — genau das, was die
Byte-Spalte misst. Es zeigt den Schätzer bei der Arbeit, keine unabhängige
Bestätigung. Bewertet wird die Reparatur an den Tests:
`test_token_estimator.py` hält die Schätzung gegen die tatsächliche serialisierte
Länge für acht Antwortformen (numerisch, base64, verschachtelt, all-null, leer).

### `strict` erstmals ausgelöst

`collect` mit 64 gelesenen Worten, `max_result_tokens=10`, `mode="strict"` →
**HTTP 413, ein einziger `RESULT_TOO_LARGE`**. Die auslösende Schätzung ist 196.
Unter dem alten Schätzer zählte dieselbe Antwort als eine Handvoll Token und wäre
durch ein Budget von 10 unbehelligt durchgelaufen — das ist die wahrscheinlichste
Erklärung dafür, dass der Pfad nie gesehen wurde.

### Zwei Befunde, festgehalten statt geändert (in keiner Stufe)

1. **Der strict-Pfad ist innerhalb von `collect` asymmetrisch.** Eine
   Verletzung auf Query-Ebene wird gefangen und als ein fehlgeschlagenes
   Teilergebnis zurückgegeben, der Rest des Batches bleibt. Eine Verletzung auf
   Request-Ebene propagiert aus `execute_collect` heraus, der ganze Batch fällt.
   Beim Aufrufer landet beides als `RESULT_TOO_LARGE` — beide Aufrufer wandeln
   um —, aber einmal partiell, einmal total.
2. **`auto_trim` ist nur insofern weich, als es nicht wirft.** Das verworfene
   Teilergebnis wird weiterhin mit `RESULT_TOO_LARGE` und `truncated=true`
   markiert. Das ist richtig so: ein weggelassenes Ergebnis, das wie ein
   geliefertes aussieht, wäre Stufe 2 von vorn.

Golden-Snapshots neu erzeugt; die Schätzungen in `collect`- und
`analyze`-Metadaten steigen um etwa das 3,5-fache — das ist die Korrektur selbst.
Antwort-Bytes 186 066 → **186 070**: vier Bytes, von den längeren Zahlen in
ebendieser Metadata.

Sockel unverändert 7610. 391 Tests grün, 10 übersprungen.

---

## Stufe 3 — Antwortvolumen (Commit `932bf3c`)

**Antwort-Bytes im Referenzlauf 186 070 → 90 914, −51 %, erstmals null Fehler.**

### Defaults auf 20

Überall, wo eine Seitengröße 50, 100 oder 200 war — in den Tool-Signaturen, den
Feature-Funktionen und den `collect`-Op-Handlern, damit die drei Oberflächen
übereinstimmen. Die hohen Werte bleiben als expliziter Parameter erreichbar.

| Aufruf, gleiche Query | alt | neu | Δ |
|---|---:|---:|---:|
| search_scalars_with_context | 80 225 | 15 969 | −80 % |
| search_scalars | 10 107 | 2 144 | −79 % |
| find_in_function | 6 364 | 6 364 | 0 % |
| search_functions / _strings / list_functions_in_range | | | ~0 % |

**Die Nullen sind ehrlich:** diese Queries liefern auf diesem Programm weniger
als 20 Treffer, das alte Limit hat sie nie gebunden. Die Ersparnis sitzt genau in
den zwei Tools, die Stufe 0 benannt hat.

### Trunkierung ohne `total`

Jede paginierte Antwort führt `truncated`. Ein unbekanntes `total` ist **abwesend**
statt `null`. `truncated` ist bewusst kein Alias für `has_more`: eine harte
Kappung pro Request trunkiert, ohne dass es etwas zum Weiterblättern gäbe.

> **Bruchklasse:** Aufrufer, die `data["total"]` direkt indizieren, brechen —
> unser eigener Contract-Test und ein Live-Test taten es, so ist es aufgefallen.
> `data.get("total")` ist unberührt. Die zwei Konsumentenprojekte konnte ich von
> hier nicht prüfen; falls eines indiziert, ist das die Zeile.

### `fmt="text"`

Eine Zeile als JSON kostet 71 Zeichen für 34 Zeichen Information; als
`00200d7c: C53400EB bl 0x0020e098` kostet sie 34.

| Aufruf, gleiche Menge | json | text | Δ |
|---|---:|---:|---:|
| disassemble_at count=16 | 1 209 | 617 | −49 % |
| disassemble_batch 4×16 | 4 999 | 2 631 | −47 % |
| scalars_ctx limit=20 | 15 969 | 9 189 | −42 % |

Format wie das, was `find_in_function` schon ausgibt. `json` bleibt Default.

> **Offene Entscheidung vor Stufe 7:** `fmt` ist Opt-in, das eingefrorene
> Referenzskript übergibt es nicht. Die −51 % oben sind **vollständig
> Default-Effekt**; der strukturelle Block in Stufe 7 bleibt sonst leer. Soll
> `text` der Default werden? Das bricht Aufrufer, die Felder parsen.

### `search_imports` repariert

Der Java-Plugin rendert jede Adresse als `"0x" + address.toString()`. Für den
Default-Adressraum richtig, für einen benannten falsch — Ghidra schreibt die
schon als `SPACE:offset`. Der einzige Import des Programms kam als
`0xEXTERNAL:00000001` an und fiel durchs Schema. In der Bridge normalisiert
(kein Plugin-Rebuild), Pattern auf `SPACE:offset` erweitert, die kaputte Form
weiterhin abgewiesen. Referenzlauf: **0 Fehler**.

Sockel 7 610 → 7 750 für die drei `fmt`-Parameter (geschätzt ~120, tatsächlich
140). Unter der Decke, die nach Rahmen 6 ein Geländer ist, kein Ziel.
422 Tests grün, 10 übersprungen.

---

## Stufe 3 — Nachtrag (Commit `7331b4f`)

### Die schlafenden Live-Contract-Tests

`test_search_endpoints_min.py:177` forderte `total` als Pflichtfeld,
`test_has_more_all_searches.py` ebenso. **Beide liefen nie** — gated auf
`RUN_LIVE_TESTS`, das niemand setzt. Sie übersprangen sich seit vor diesem Rework.

Beide laufen jetzt über `bridge/tests/contract/_live_bridge.py`, das zwei Arten
des Falschliegens ausschließt:

- **Keine Bridge da** → Skip mit der URL im Grund. Nie ein Bestehen.
- **Bridge da, aber anderes Binary** → Skip mit beiden Prüfsummen. Aussagen über
  `ZK-INKJET-NANO-APP.bin`, die gegen ein anderes Programm bestehen, sind wertlos.

Beide Pfade verifiziert.

**Beim ersten echten Lauf fiel ein zweiter schaler Test auf:**
`test_strings_pagination_is_deterministic` forderte Seite 101 bei Limit 20 — ein
Fenster von 2020 gegen eine Batch-Decke von 256. Der Server antwortet 413, die
Assertion dahinter war unerreichbar. Auf eine erreichbare Seite korrigiert, und
das Deckenverhalten als eigener Test festgehalten: ein zu weites Fenster muss
laut scheitern, eine leere Seite wäre von „keine weiteren Treffer" nicht zu
unterscheiden.

### `scripts/reference_run_structural.py`

Zweites eingefrorenes Skript. Übergibt die Limits von vor Stufe 3 explizit und
setzt `fmt="text"` — gleiche angeforderte Menge vorher wie nachher, übrig bleibt
Effizienz pro geliefertem Ergebnis. Teilt die Fingerabdruck-Maschinerie mit dem
Baseline-Skript per Import statt per Kopie: zwei Skripte, die sich über die
gemessene Datenbank uneinig sind, wären schlimmer als kein Fingerabdruck.

### `fmt="text"` als MCP-Default

Nur auf der MCP-Oberfläche der drei Disassemblat-Tools; HTTP behält `json`.
Begründung: MCP bedient ein Modell, das Listings **liest** — Text kostet die
Hälfte und liest sich gleich. HTTP bedient Programme, die Felder **parsen** — dort
wäre eine Formänderung ein stiller Bruch. Die Aufteilung ist getestet, auch die
Hälfte, die eine Abwesenheit ist (keine Route reicht ein Listing-`fmt` durch).

### Die zwei Zahlen, getrennt

| | Bytes | Δ |
|---|---:|---:|
| vor Stufe 3 | 186 070 | |
| **strukturell** (gleiche angeforderte Menge) | 133 977 | **−28 %** |
| **mit gesenkten Defaults zusammen** | 72 618 | **−61 %** |

| Tool | vor St. 3 | strukturell | + Defaults |
|---|---:|---:|---:|
| search_scalars_with_context | 111 662 | 64 565 | 18 702 |
| find_in_function | 20 013 | 20 013 | 13 912 |
| search_scalars | 15 152 | 15 196 | 5 358 |
| analyze_function_complete | 11 633 | 11 633 | 11 633 |
| disassemble_at | 5 026 | 2 658 | 2 658 |
| disassemble_batch | 5 035 | 2 667 | 2 667 |

`analyze_function_complete` ist von dieser Stufe unberührt — 11 633 Bytes aus zwei
Aufrufen, jetzt der zweitgrößte Posten. Kandidat, falls nach Stufe 4 noch etwas
gesucht wird.

Sockel 7 750 → 7 756. 469 Tests grün.

**Vorbestehend, in keiner Stufe, nicht angefasst:** drei Fehler in
`bridge/tests/plan` — `.ci/AGENT_LOCK` trägt `expires_at 1767225600` (2026-01-01),
die Plan-Tests prüfen, dass das in der Zukunft liegt.

---

## Korrektur — die Testzahlen (Commit `b69ae5a`)

**Alle bisherigen Grün-Meldungen in diesem Dokument waren Teilmengen.** Der
Aufruf `pytest bridge/tests/unit bridge/tests/contract bridge/tests/golden
bridge/tests/live` sammelt 435 Tests. Die Suite hat **472**. Die fehlenden 37
liegen in `bridge/tests/integration` (12), `bridge/tests/obs` (3),
`bridge/tests/plan` (6) und `bridge/tests/test_request_validation.py` (16) — und
darunter waren drei echte Fehler, die über mehrere Stufen unberichtet blieben.

Die berichteten Zahlen der Stufen 0 bis 3 sind damit als „Teilmenge grün" zu
lesen, nicht als „Suite grün".

**Verbindlicher Aufruf ab sofort:**

    scripts/run_tests.sh

Nimmt den Wurzelpfad und sonst nichts, findet das venv auch aus einem Worktree,
reicht zusätzliche Argumente durch. Keine Verzeichnisaufzählung mehr — ein grünes
Teilergebnis liest sich exakt wie ein grünes Gesamtergebnis.

Stand nach dieser Korrektur, mit laufender Ghidra-Instanz und laufender Bridge:
**472 gesammelt, 470 grün, 2 rot.** Ohne Bridge auf :8000: 459 grün, 11
übersprungen (mit spezifischem Grund).

### `.ci/AGENT_LOCK`

Trug `expires_at 1767225600` (2026-01-01) und `branch "work"`. Jetzt der
Arbeitsbranch mit zwei Wochen Lease. Behebt `test_agent_metadata_files_exist_and_valid`.

### Zwei Plan-Fehler bleiben — offen, nicht meine

`bin/plan_check.py` meldet vier IDs, die in `.plan/TODO.md` stehen und in
`.plan/state.json` fehlen: **BUILD.1, DIAG.3, DIAG.4, R.29**. Alle vier stehen
unter NEXT, die Einträge wären also `{"status": "todo", "commit": "pending"}` —
mechanisch, aber es ist Planungsstand und nicht ungefragt von mir zu schreiben.
Ein Wort genügt, dann ist es ein Commit.

### Stufe-2-Regressionstest: hängt **nicht** am Gate

`bridge/tests/live` setzt `RUN_LIVE_TESTS` auf default **an**; der Test läuft,
sobald Ghidra antwortet. Sein Skip-**Grund** log jedoch: bei abgeschaltetem Flag
meldete er „no Ghidra instance", während Ghidra lief. Eine Meldung, die falsch
angibt, warum nichts geprüft wurde, ist genau die Fehlerklasse, gegen die diese
Suite gebaut ist. Die Sonde unterscheidet jetzt vier Fälle, alle verifiziert:

    live tests disabled (RUN_LIVE_TESTS=0)
    Ghidra at http://127.0.0.1:9999/ returned no project info
    Ghidra at http://127.0.0.1:8080/ is serving a different program (sha256 …)
    20 passed

Die Identitätsprüfung liegt jetzt in der Sonde, nicht im `client`-Fixture — ein
falsches Programm wird abgewiesen, bevor irgendein Fixture einen Client ausgibt.

### `analyze_function_complete` — gemessen, nicht umgebaut

**Ja, der `fields`-Default ist die Ursache.** Ein Default-Aufruf fordert alle
sieben Felder: 5 626 Bytes.

| Feld | Bytes | Anteil | isoliert angefordert |
|---|---:|---:|---:|
| decompile | 2 022 | 36 % | 2 183 |
| disasm | 1 252 | 22 % | 1 407 |
| xrefs | 678 | 12 % | 831 |
| strings | 671 | 12 % | 828 |
| callgraph | 324 | 6 % | 484 |
| function | 215 | 4 % | 373 |
| features | 156 | 3 % | 314 |
| meta | 179 | 3 % | — |

`decompile` und `disasm` sind zusammen 58 %. Wer nur `function` + `xrefs`
braucht, zahlt 5 626 statt gut 1 000.

**Zweiter Befund:** `disasm` ist ein Listing, aber das `fmt` von
`analyze_function_complete` akzeptiert ausschließlich `"json"` — ein anderer
Parameter als das Listing-`fmt` aus Stufe 3. Das eingebettete Disassemblat
profitiert also **nicht** von der Textform, obwohl es dieselben Zeilen sind.
Beides steht in keiner Stufe; nichts umgebaut.

---

## Stufe 3 — Arbeitspaket `analyze_function_complete` (Commit `2723614`)

Nachgetragen zu Stufe 3, keine eigene Stufe.

`fields` steht jetzt auf **function + xrefs + strings + features**. `disasm` und
`decompile` sind draußen — gemessen an 0x002AF9C0 sind sie 22 % und 36 % eines
vollen Dossiers, zusammen 58 %, und beide sind zu besseren Konditionen einzeln zu
haben, sobald die billigen Felder gesagt haben, ob das die richtige Funktion ist:
`disassemble_at` liefert das Listing als Text zum halben Preis,
`find_in_function` nur die passenden Zeilen.

| | alle sieben | neuer Default | Δ |
|---|---:|---:|---:|
| 0x002AF9C0 | 5 626 | 1 949 | −65 % |
| 0x002AF80C | 5 935 | 1 783 | −70 % |
| Referenzlauf, Anteil `analyze` | 11 633 | 3 804 | −67 % |
| **Referenzlauf gesamt** | **72 618** | **64 789** | **−11 %** |

Ein genanntes Feld **ersetzt** den Default, es ergänzt ihn nicht. Das war schon
so, steht jetzt in der Beschreibung und ist per Test festgenagelt.

**Das strukturelle Skript musste korrigiert werden, nicht eingefroren wie es war.**
Es rief `analyze` ohne `fields` auf, der Default-Wechsel erschien dort also als
Ersparnis — aber genau dieses Skript soll die angeforderte Menge konstant halten.
Es nennt jetzt alle sieben Felder explizit, und sein Gesamtwert bleibt bei
**133 977**, was für eine Stufe, die an diesen Aufrufen nichts geändert hat, der
richtige Wert ist.

### Bekannte Macke, nicht gebaut: das doppelte `fmt`

`analyze_function_complete` hat einen Parameter `fmt`, der ausschließlich `"json"`
akzeptiert — ein anderer Parameter als das Listing-`fmt` aus Stufe 3. Ein
eingebettetes `disasm`-Feld kommt deshalb immer als Objektliste, nie als
gerenderte Zeilen, obwohl es dieselben Zeilen sind, die `disassemble_at` zum
halben Preis ausgibt. Zwei Parameter gleichen Namens mit verschiedener Bedeutung
in derselben Oberfläche. **Notiert, nicht behoben.** Seit der Default `disasm`
nicht mehr enthält, ist die praktische Auswirkung klein.

### Plan-Zustand

`BUILD.1`, `DIAG.3`, `DIAG.4`, `R.29` in `.plan/state.json` ergänzt.
`plan_check` verlangte dieselben drei zusätzlich in `.plan/tasks.manifest.json`;
die Einträge tragen je eine Notiz, dass ihr Umfang die TODO-Zeile ist und nichts
darüber hinaus — der Eintrag existiert, damit die Prüfung durchläuft, nicht weil
jemand den Entwurf entschieden hätte.

    scripts/run_tests.sh, mit Bridge auf :8000:   472 grün
    ohne Bridge:                                  461 grün, 11 übersprungen

---

## Nachtrag — Vollständigkeit des strukturellen Skripts

Vollprüfung aller Aufrufe gegen alle Tool-Signaturen: **dreizehn weitere
Mengenparameter standen implizit** (nicht nur der bereits behobene `fields`):

| Aufruf | fehlte |
|---|---|
| search_functions (5×) | context_lines |
| search_strings (3×) | include_literals |
| strings_compact | offset, include_literals |
| read_words (2×), read_bytes | include_literals |
| find_in_function (2×) | mode, regex, case_sensitive, **context_lines** |
| search_xrefs_to (2×) | page |
| mmio_annotate_compact | max_samples |
| analyze_function_complete (2×) | fmt, max_result_tokens, **options** |

Dazu die `collect`-Unterqueries. Alle stehen jetzt explizit auf den Werten von
vor Stufe 3; `analyze` bekommt seine sämtlichen `options`-Grenzen ausgeschrieben.

**Der Wert bleibt bei 133 977.** Alle dreizehn standen zufällig noch auf ihrem
alten Default — das Skript war also glücklich, nicht korrekt. `context_lines` bei
`find_in_function` und der ganze `options`-Block von `analyze` sind die, bei denen
ein späterer Default-Wechsel deutlich sichtbar geworden wäre.

Die Prüfung liegt als Test vor (`test_structural_run_completeness.py`), samt
Absicherung gegen sich selbst: ein Parse, der still nichts findet, fällt durch,
und wer die Parameterliste kürzt, ebenfalls.

---

## Stufe 4 — Filter für `disassemble_batch` (Commit `6d91e3d`)

`query`, `regex`, `case_sensitive`, `context_lines` mit der Semantik von
`find_in_function`: gematcht wird gegen die **gerenderte Zeile**, Adresse und
kodierte Bytes sind also mitdurchsuchbar, und eine literale Query wird escaped
statt interpretiert (`[0x2afb34]` findet den Operanden, statt zu werfen).
Durchgereicht bis in den `collect`-Op und beide Schemata.

**Ohne `query` ändert sich nichts** — weder Verhalten noch Antwortschlüssel. Mit
`query` kommen `filter` (was gefragt wurde) und `summary` mit
`scanned`/`matched`/`returned` dazu. `returned` übersteigt `matched`, sobald
Kontext angefordert ist; die Lücke zwischen `scanned` und `returned` ist das, was
der Filter entfernt hat. Ein gefiltertes Listing darf nicht wie ein vollständiges
lesbar sein.

### Abnahme: alle `ldr`-Pool-Zugriffe in diesen vier Funktionen

| | Bytes | Δ |
|---|---:|---:|
| **strukturell**, `fmt=json`, gleiche Menge | | |
| ohne Filter (64 Instruktionen) | 4 999 | |
| mit Filter (11 Instruktionen) | 1 166 | **−77 %** |
| **mit MCP-Default**, `fmt=text` | | |
| ohne Filter | 2 631 | |
| mit Filter | 759 | **−71 %** |
| **gegen den Stufe-0-Ausgangswert** | | |
| Stufe 0 — json, ungefiltert | 4 999 | |
| Stufe 3 — text, ungefiltert | 2 631 | −47 % |
| Stufe 4 — text, gefiltert | **759** | **−85 %** |

Zum Vergleich, wie diese Frage bisher beantwortet wurde: **vier
`find_in_function`-Aufrufe, 17 724 Bytes** über vier Round-Trips, für dieselben
elf Zeilen.

### Zwei Geländer haben gegriffen

**Rahmen 8** — der Vollständigkeitstest fing die vier neuen Parameter, die im
strukturellen Skript auf ihrem Default standen. Genau wofür er da ist. Dort jetzt
benannt; der Lauf bleibt bei 133 977, was für einen Opt-in-Filter richtig ist.

**Rahmen 6** — die Sockel-Decke ist gefallen: 7 756 → **8 198**. Neu gesetzt auf
**8 400**, mit Begründung im Test statt drumherum getrimmt. Die vier Parameter
kosten 442 Token Schema, einmal pro Sitzung. Sie kaufen einen Aufruf, der von
4 999 auf 792 Bytes fällt — und der wird jedes Mal bezahlt.

486 Tests grün, 11 übersprungen.

---

## Stufe 6 — entschieden: wird nicht gebaut (2026-08-20)

Begründung steht oben bei der Stufe. Kurz: das Budgetargument ist seit Rahmen 6
hinfällig, das Ambiguitätsargument ist real, hat sich aber über sechs Stufen
Arbeit an genau dieser Oberfläche **kein einziges Mal** als Fehlwahl gezeigt.
Umbau ohne belegtes Problem, an der einzigen Stelle, die zwei Projekte brechen
kann. Bleibt als Option notiert; eine echte Fehlwahl wäre der Anlass.

---

## Stufe 5 — Mutationen exportierbar (Commit `06a581a`)

### `list_mutations`

Sitzungsjournal über Umbenennungen, Kommentare, Datentyp-Änderungen und
Byte-Patches, mit Adresse, altem und neuem Wert, gerendert als Block für eine
Commit-Message oder eine TRUTH-Zeile. Es beantwortet, was `check_dirty_state`
nicht kann: das Tool weiß, *dass* etwas offen ist, dieses weiß, *was*.

**Abnahme** gegen die eingefrorene Kopie — drei probeweise Renames im Dry-Run,
das Tool listet genau diese drei:

    [proposed] 0x002af9c0  rename    usbd_init_phy_cep -> usbd_init_phy_cep_v2
    [proposed] 0x002af80c  rename    usbd_irq_setup    -> usbd_irq_setup_v2
    [proposed] 0x0026a7f8  rename    ui_main_loop      -> ui_main_loop_v2
    {"total": 3, "applied": 0, "proposed": 3, "by_kind": {"rename": 3}}

Drei Unterscheidungen, auf denen das Journal besteht:

- **Vorschläge werden erfasst und markiert.** Ein Dry-Run-Rename ist eine
  getroffene Entscheidung und gehört notiert — trägt aber `[proposed]`. Ein
  Journal, in dem eine Absicht wie eine Tat liest, ist schlimmer als keines.
- **Unbekannt ist nicht leer.** `?` gegen `(empty)` sind verschiedene Aussagen
  über das Binary.
- **Zurückgesetzt wird nur bei einem Speichern, das wirklich gespeichert hat.**
  `save_program` meldet jetzt `mutations_cleared`.

**Ein Befund beim Bauen:** die alten Namen kamen zunächst alle als `?`. Der
Plugin antwortet auf `get_function_by_address` mit
`{"Function": "<name> at <address>"}` — großgeschrieben und mit dem Namen in
einem Satz statt in einem eigenen Feld. Das naheliegende `meta.get("name")`
liefert `None`. Der erste Abnahmelauf sah dadurch korrekt aus und war es nicht.

**Vorbestehend, nicht angefasst:** `bridge/features/jt.py` liest `pre_name` und
`pre_comment` genauso falsch — seine Audit-Einträge haben also seit jeher `None`
aufgezeichnet. In keiner Stufe.

**Alte Kommentare gibt es nicht.** Der Plugin hat keinen Endpunkt, der einen
bestehenden Kommentar zurückgibt. Statt einen Round-Trip auszugeben, um nichts zu
erfahren, steht das im Helfer und wird als `?` gerendert.

### Die `strict`-Asymmetrie

Eine Budgetverletzung auf Request-Ebene propagierte aus `execute_collect` heraus
und nahm den ganzen Batch mit; eine auf Query-Ebene verwarf ein Teilergebnis und
ließ den Rest stehen. **Beide sind jetzt partiell**, und
`meta.dropped_by_budget` **nennt** die betroffenen Query-IDs — genannt, nicht
gezählt, denn ein partieller Batch darf nicht wie ein vollständiger lesen. Zwei
Tests, die das alte Verhalten festnagelten, wurden nachgezogen statt umgangen;
die HTTP-Route liefert 200 mit fehlgeschlagenem Teilergebnis statt 413.

Decke 8 400 → **8 700**, Grund im Test: `list_mutations` ist ein 36. Tool zu 274
Token. Beide Referenzläufe unverändert (64 789 und 133 977) — diese Stufe fasst
keinen Lesepfad an. 507 Tests grün, 11 übersprungen.

---

# Stufe 7 — Nachmessen (Abschluss)

Beide Läufe unverändert eingefroren, dasselbe Logging, derselbe Fingerabdruck.

**Datenbank-Identität, in beiden Läufen geprüft und übereinstimmend:**

    ZK-INKJET-NANO-APP.bin.orig
    sha256 3be9028b01c0007aab9192877341918a0bc155beef55ac17e7e8f3bcc95151ea
    1266 Funktionen, davon 24 benutzerbenannt
    -> matches the expected fingerprint   (beide Läufe, sonst keine Auswertung)

Beide Läufe: 40 Aufrufe, **0 Fehler** (Stufe 0: 1).

## Die zwei Blöcke, nach Tool

`struktur` = gleiche angeforderte Menge wie in Stufe 0, `fmt="text"`, Filter
verfügbar aber ungenutzt. `default` = Aufruf ohne Mengenparameter, wie eine
unbedarfte Sitzung ihn macht.

| Tool | n | Stufe 0 | struktur | default |
|---|--:|--:|--:|--:|
| search_scalars_with_context | 2 | 111 662 | 64 565 | **18 702** |
| find_in_function | 2 | 20 013 | 20 013 | 13 912 |
| search_scalars | 3 | 14 451 | 15 196 | 5 358 |
| analyze_function_complete | 2 | 11 631 | 11 633 | 3 804 |
| disassemble_batch | 1 | 5 035 | 2 667 | 2 667 |
| disassemble_at | 4 | 5 026 | 2 658 | 2 658 |
| collect | 2 | 3 934 | 3 384 | 3 974 |
| search_strings | 3 | 3 537 | 3 597 | 3 461 |
| string_xrefs_compact | 1 | 1 833 | 1 833 | 1 833 |
| list_functions_in_range | 2 | 1 431 | 1 471 | 1 469 |
| search_functions | 5 | 1 395 | 2 419 | 2 414 |
| mmio_annotate_compact | 1 | 999 | 999 | 999 |
| project_info | 1 | 897 | 897 | 897 |
| search_exports | 1 | 636 | 656 | 655 |
| search_xrefs_to | 2 | 480 | 520 | 518 |
| project_overview | 1 | 441 | 441 | 441 |
| read_words | 2 | 292 | 292 | 292 |
| search_imports | 1 | 211 | 199 | 198 |
| read_bytes | 1 | 197 | 197 | 197 |
| check_dirty_state | 1 | 164 | 164 | 164 |
| get_current_program | 1 | 115 | 115 | 115 |
| strings_compact | 1 | 61 | 61 | 61 |
| **Summe** | **40** | **184 441** | **133 977** | **64 789** |

**Strukturelle Ersparnis: −27 %** gegen 184 441, −28 % gegen die Byte-Baseline
186 070 ab Stufe 2. Sie stammt aus `fmt="text"` (`disassemble_at` −47 %,
`disassemble_batch` −47 %, `search_scalars_with_context` −42 %). Der
Stufe-4-Filter ist hier **nicht** enthalten — er ist opt-in, und der eingefrorene
Lauf ruft ihn nicht auf. Am realen Fall gemessen bringt er zusätzlich −77 % auf
diesen einen Aufruf.

**Default-Effekt: −65 %.** Das ist, was eine Sitzung spart, die keine Parameter
setzt — überwiegend die gesenkten Limits und der schmalere `fields`-Default von
`analyze_function_complete`. Weniger angefordert, weniger geliefert; als das zu
benennen und nicht als Effizienz.

## Der Schema-Sockel als Gegenposten

Er ist keine Fußnote, sondern die Rechnung: **5 406 → 8 489 Token, +57 %**,
einmal pro Sitzung.

| Stufe | Sockel | Treiber |
|---|--:|---|
| 0 — Baseline | 5 406 | 16 von 35 Tools ohne Beschreibung |
| 1 — Beschreibungen, erster Anlauf | 11 334 | 26 Tools neu beschrieben |
| 1 — getrimmt | 7 804 | knappe Hausform, Blindflecktext nach `method_notes.py` |
| 1 — letzte sieben | 7 610 | Alt-Beschreibungen nachgezogen |
| 3 — `fmt` | 7 756 | drei Listing-Parameter |
| 4 — Batch-Filter | 8 198 | `query`, `regex`, `case_sensitive`, `context_lines` |
| 5 — `list_mutations` | **8 489** | 36. Tool |

Bei 40 Aufrufen sind 8 489 Token Sockel gegen 16 197 Token Antwort (64 789 / 4)
etwa ein Drittel der Sitzung; bei zweihundert Aufrufen ein Zehntel. Vor dem
Rework: 5 406 gegen 46 110. **Der Sockel ist absolut gestiegen und relativ
gewachsen** — er wird bei kurzen Sitzungen teurer bezahlt als vorher. Das ist der
Preis dafür, dass 36 von 36 Tools beschrieben sind und jeder Parameter einen
dokumentierten Wertebereich hat.

## Das Ghidra-Plugin wurde nicht angefasst

Kein Java geändert, kein Rebuild, keine Neuinstallation. Drei Befunde haben ihre
**Ursache im Plugin** und ihre **Behandlung in der Bridge**:

1. **`search_imports`** — der Plugin bildet jede Adresse als
   `"0x" + address.toString()`. Für den Default-Adressraum richtig, für einen
   benannten falsch: Ghidra schreibt die schon als `SPACE:offset`. Der einzige
   Import des Programms kam als `0xEXTERNAL:00000001` und fiel durchs Schema.
   In der Bridge normalisiert.
2. **`get_function_by_address`** — antwortet in Prosa
   (`{"Function": "<name> at <hex>"}`) statt in Feldern. In der Bridge mit
   verankertem Muster und Adress-Gegenprobe geparst; passt es nicht, gibt es `?`
   statt eines geratenen Teilstrings.
3. **Kein Endpunkt für bestehende Kommentare.** `list_mutations` kann den alten
   Kommentarwert deshalb nicht auflösen und rendert `?`.

Dazu ein vorbestehender Fehler, der aus derselben Wurzel stammt:
**`bridge/features/jt.py` parst `pre_name` und `pre_comment` mit
`meta.get("name")`** — ein Feld, das es nicht gibt. Seine Audit-Einträge zeichnen
seit jeher `None` auf. Nicht angefasst, weil in keiner Stufe.

**Eine Plugin-Runde ist eine eigene Entscheidung nach dem Rework, kein Teil
davon.** Sie würde 1–3 an der Quelle beheben und die Bridge-Umgehungen
überflüssig machen.

## Was nicht besser wurde

**Sechs Tools sind teurer als vorher:**

| Tool | Stufe 0 | nachher | Ursache |
|---|--:|--:|---|
| search_functions | 1 395 | 2 414 | +73 % |
| search_xrefs_to | 480 | 518 | +8 % |
| search_exports | 636 | 655 | +3 % |
| list_functions_in_range | 1 431 | 1 469 | +3 % |
| collect | 3 934 | 3 974 | +1 % |
| search_scalars (strukturell) | 14 451 | 15 196 | +5 % |

`search_functions` aufgeschlüsselt, Aufruf für Aufruf:

    vorher   usb 447(5)  init 311(3)  boot 315(3)  dma 160(0)  print 162(0)
    nachher  usb 466(5)  init 330(3)  boot 334(3)  dma 641(0)  print 643(0)

Die drei Treffer-Aufrufe wachsen um je 19 Bytes (`truncated`). Die zwei **leeren**
wachsen um je 481 Bytes — der `method_note` aus Stufe 2. Das ist kein Nebeneffekt,
sondern der Zweck: eine leere Antwort kostet jetzt mehr und sagt dafür, was der
Suchmodus nicht sehen kann. Der Referenzlauf hat einen ungewöhnlich hohen Anteil
leerer Suchen, weil `0xB1008000` absichtlich darin steht.

**Acht Tools sind unverändert** — `string_xrefs_compact`, `mmio_annotate_compact`,
`project_info`, `project_overview`, `read_words`, `read_bytes`,
`check_dirty_state`, `get_current_program`, `strings_compact`. Keine Stufe hat sie
adressiert. `string_xrefs_compact` (1 833 Bytes) und `mmio_annotate_compact` sind
die einzigen darunter, die groß genug wären, um sich zu lohnen.

**`find_in_function` ist strukturell unverändert** (20 013). Es filterte schon
vorher serverseitig; nur der gesenkte Default bringt etwas (−30 %). Ein
`fmt="text"` für seine Kontextzeilen wäre der offensichtliche nächste Schritt und
steht in keiner Stufe.

**Das doppelte `fmt` bleibt.** `analyze_function_complete` hat einen Parameter
`fmt`, der ausschließlich `"json"` akzeptiert — anderer Parameter, gleicher Name,
andere Bedeutung als das Listing-`fmt`. Ein eingebettetes `disasm`-Feld kommt
deshalb immer als Objektliste. Notiert, nicht behoben.

**Vierzehn der 36 Tools kommen im Referenzlauf nicht vor** und tragen 3 070 der
8 489 Sockel-Token — 36 % des Sockels ohne gemessenen Nutzen:
`jt_slot_process` (368), `datatypes_create` (312), `jt_slot_check` (296),
`list_mutations` (274), `jt_scan` (250), `datatypes_update` (238),
`set_comment` (214), `project_rebase` (204), `write_bytes` (180),
`select_program` (175), `datatypes_delete` (162), `save_program` (146),
`rename_function` (145), `goto_address` (106).

Das ist keine Aussage über ihre Nützlichkeit — der Referenzlauf ist lesend, die
meisten davon schreiben. Es ist eine Aussage darüber, dass **ihr Nutzen in diesem
Rework nicht gemessen wurde**. Für die `jt_*`-Familie (914 Token) war genau das
die offene Frage aus Stufe 6, und sie ist weiterhin offen.

**Stufe 6 wurde nicht gebaut** — siehe Entscheidung oben.

## Stand

    Tests            526 grün, 11 übersprungen (mit spezifischem Grund)
    Aufruf           scripts/run_tests.sh
    Antwort-Bytes    184 441 -> 133 977 strukturell / 64 789 mit Defaults
    Schema-Sockel    5 406 -> 8 489
    Fehler im Lauf   1 -> 0
    Plugin           unverändert

---

# Sitzungsabschluss (2026-08-20)

Der Rework selbst endet mit Stufe 7 (`d615764`). Danach lief eine Nacharbeitsphase
aus fünf weiteren Commits, die nicht Teil des Plans war, sondern aus dem
Abklopfen der laufenden Instanz entstand. Sie steht hier, weil sie denselben
Befundtyp betrifft und die Stufe-7-Zahlen verschiebt.

## Nach Stufe 7

| Commit | Was |
|---|---|
| `a0c9076` | Plugin: `onProgramActivated` erzwingen, wenn `open_program` ein bereits offenes Programm trifft |
| `a807184` | MMIO-Basisauflösung: `MOV`-Immediate, kein Offset-Raten, `skipped` ausgewiesen |
| `a73a13b` | `apply_label` als R.12 geschärft, Ghidra-Skript ins Repo |
| `b194726` | `strings_compact` überhaupt zum Laufen gebracht |
| `973cab1` | Drei Feldtest-Befunde: `total`-Form, Hex-Worte, Poolwörter als Strings |

**Der Fehlgriff dieser Sitzung, festgehalten:** bei Stufe 4 begann eines meiner
Skripte mit `cd` ins Hauptrepo, das nachfolgende `git add -A && git commit` lief
dadurch dort auf `main` und schluckte ein privates Chatprotokoll, das
Plan-Dokument und eine fremde Java-Änderung. Zurückgenommen per
`reset --mixed`, nichts verloren, nichts gepusht.

**Und dann ein zweites Mal**, bei `a807184`, im selben Muster und unbemerkt —
während ich den Absatz oben schrieb. Erst der `git status` beim Sitzungsabschluss
hat es gezeigt: das Chatprotokoll steckte seit fünf Commits in der History. Per
`filter-branch` über `a0c9076..HEAD` entfernt, `refs/original` gelöscht, Reflog
abgelaufen, Datei im Arbeitsverzeichnis erhalten und jetzt in `.gitignore`. Das
Plandokument bleibt bewusst getrackt.

Die Lehre gehört in Rahmen 8, steht dort aber nicht: **ein `cd` am Anfang eines
Skripts wirkt bis zum Ende des Befehls, und `git add -A` fasst alles, was dort
liegt.** Dass ich sie beim ersten Mal formuliert und beim zweiten Mal trotzdem
verletzt habe, ist der eigentliche Befund — eine notierte Lehre ersetzt keine
Gewohnheit. Was hier getragen hätte: Pfad explizit angeben statt `-A`.

## Zahlen zum Schluss

    Referenzlauf (Default)    184 441 -> 67 710 Bytes, 0 Fehler (Stufe 0: 1)
    Referenzlauf (strukturell) 184 441 -> 133 977 Bytes
    Schema-Sockel               5 406 -> 8 592 Token (Decke 8 700)
    Tools                          35 -> 36
    Tests                         314 -> 540 grün, 11 übersprungen
    Fingerabdruck             unverändert, in beiden Läufen geprüft

Die Byte-Zahl liegt über dem Stufe-7-Wert von 64 789, weil `strings_compact`
seither überhaupt etwas liefert (+3 588) und `analyze` weniger Falschbefunde
(−988). Beides sind Korrekturen, keine Regressionen.

## Der rote Faden

Jeder Befund dieser Sitzung hatte dieselbe Form: **kein Fehler, keine Warnung,
nur eine Antwort, die aussah wie eine Aussage über die Firmware.**

- `search_scalars` fand nichts und meinte nichts — sieben Monate blockiert.
- `strings_compact` lieferte auf jedem Programm `{"total": 0, "items": []}`.
- `mmio_annotate_compact` erfand Registeradressen aus Stack-Offsets.
- `search_imports` scheiterte am eigenen Schema.
- Die Live-Contract-Tests liefen nie und meldeten trotzdem grün.
- `total` verschwand genau dann, wenn ein Konsument es zum ersten Mal brauchte.
- `analyze` nannte Konstantenpool-Worte „Strings".
- Der Skip-Grund log über die eigene Ursache.

Deshalb die Rahmenregeln 5 bis 8, und deshalb ist die Abnahme jeder Stufe eine
Messung und keine Behauptung.

## Hand-off: was offen ist

> **Abgelöst** durch das Hand-off vom 2026-10-10 am Ende dieses Dokuments. Erledigt seither:
> Push (alle Commits auf `origin/main`), Plugin-Rebuild, R.12 `apply_label`, `JT-PRENAME-PARSE`,
> `ANALYZE-POOL-CONSTANTS`, `find_in_function` `fmt="text"`, `DOC-DEFAULT-DRIFT`. Unverändert
> offen: das doppelte `fmt` von `analyze_function_complete` (nur die Beschreibung ist kürzer),
> `save_program` mit `program_name: null`, der Nutzen der `jt_*`-Familie.

**Vor dem Push** (nichts davon ist meine Entscheidung):

1. `origin/main` steht auf `c292fdc` (9. Januar). **22 Commits ungepusht**,
   darunter der März-Commit mit den Datatype-Endpunkten, den außer dir niemand
   gesehen hat.
2. Zwei private Dateien liegen untracked im Wurzelverzeichnis und sind **nicht**
   in `.gitignore`: das Chatprotokoll und `ghidramcpd-rework.md`.
3. `baseline/` ist mitcommittet — rund 2 700 Zeilen JSON. Für Stufe 7 war es der
   Maßstab; ob es dauerhaft ins Repo gehört, ist zu entscheiden.
4. **Kein Plugin-Rebuild gelaufen.** `a0c9076` ist nicht compile-geprüft. Der
   nächste `./scripts/build_docker.sh` erledigt das.

**Offene Punkte im Werkzeug** (alle benannt, keiner behoben):

- **R.12 `apply_label`** — die eigentliche Blockade. Braucht Plugin-Endpunkt,
  Bridge-Tool und Rebuild. Skript und Ursachenanalyse liegen bereit.
- **`jt.py` parst `pre_name`/`pre_comment` falsch** (`meta.get("name")` auf eine
  Prosa-Antwort) und protokolliert seit jeher `None`. Gleiche Wurzel wie der in
  Stufe 5 behobene Fall, in keiner Stufe.
- **Poolwörter als eigener Abschnitt.** `analyze` verwirft sie jetzt korrekt,
  aber sie sind wertvoll (`0x8190`/`0x82B0` aus finding-0005). Als
  „Pool-Konstanten" ausgewiesen wären sie nützlicher als das Verwerfen. Feature,
  kein Fix.
- **Doppeltes `fmt`** — `analyze_function_complete.fmt` akzeptiert nur `json`
  und ist ein anderer Parameter als das Listing-`fmt`.
- **`find_in_function` ohne `fmt="text"`** — 20 013 Bytes, strukturell
  unverändert seit Stufe 0, der offensichtlichste nächste Sparposten.
- **`save_program` meldet `program_name: null`**, wenn nichts zu speichern war,
  obwohl die Beschreibung das Feld ohne Einschränkung nennt.
- **Testlücke:** kein Test gleicht Doku-Angaben gegen Signatur-Defaults ab. Genau
  daran ist mir der „default limit of 100"-Widerspruch monatelang entgangen
  wäre — gefunden hat ihn der Feldtest, nicht die Suite.
- **Vierzehn von 36 Tools** kommen im Referenzlauf nicht vor und tragen 3 070
  Sockel-Token ohne gemessenen Nutzen. Für `jt_*` (914) war das die offene Frage
  aus Stufe 6.

**Stufe 6 bleibt entschieden nicht gebaut.** Eine echte Fehlwahl wäre der Anlass,
sie neu aufzurufen.

---

## Stufe 8a — Loopback (Commit `db7d982`, Abnahme 2026-10-09)

Tool-Option `Bind Address`, Default `127.0.0.1`; ein leeres Feld heißt ebenfalls
Loopback, alle Interfaces gibt es nur mit ausgeschriebenem `0.0.0.0`, und dann mit
Warnung im Log. Java-Test (JUnit 4.13.2, 8 grün) wird rot, wenn ein leeres Feld zum
Wildcard aufgelöst wird — geprüft durch Einbau genau dieses Fehlers.

**Abnahme** nach Rebuild (`scripts/build_local.sh`) und Neustart von Ghidra,
`scripts/check_plugin_bind.sh`:

    ok: listening on [::ffff:127.0.0.1]:8080
    ok: 127.0.0.1:8080 answered (HTTP 404)
    ok: positive control reached <LAN-IP>:34715
    ok: <LAN-IP>:8080 refused
    PASS: port 8080 is reachable on loopback only

**Der erste Lauf meldete FAIL — gegen ein korrekt gebundenes Plugin.** Java öffnet
auch für eine IPv4-Bindung einen IPv6-Socket; `ss` zeigt `127.0.0.1` deshalb als
`[::ffff:127.0.0.1]`, und das Muster im Skript kannte nur `127.*` und `[::1]`. Das
Skript war vorher gegen Python-Dummies validiert (Loopback → PASS, `0.0.0.0` → FAIL,
kein Listener → CANNOT CHECK) — reine IPv4-Sockets, die diese Form nie zeigen. Eine
Validierung gegen ein Stellvertreterobjekt belegt das Stellvertreterobjekt: derselbe
Befundtyp wie die Stubs in 8b, diesmal im eigenen Prüfskript.

Nicht geprüft: der alte Plugin-Stand gegen das korrigierte Skript. Er band auf den
Wildcard, den `ss` als `*` zeigt; das Muster lässt ihn nicht durch.

## Stufe 8b — Tools ohne Gegenstück (2026-10-09)

**Geländer zuerst.** `bridge/tests/unit/test_plugin_routes.py` liest die Routen aus
`GhidraMCPPlugin.java` (51, als Zahl festgehalten, damit eine kaputte Extraktion
auffällt) und prüft sie gegen `DEFAULT_WHITELIST`, die `_request_lines` bei jedem
Aufruf erzwingt. Vor jeder Änderung rot, mit genau den sechs Schlüsseln
`START/COMMIT/ROLLBACK_TRANSACTION`, `WRITE_BYTES`, `REBUILD_CODE_UNITS`,
`REBASE_PROGRAM`.

**Korrektur an der Regel im Plan:** „jeder Pfad und jeder Alias" hätte nicht mit
sechs, sondern mit 19 Namen rot geschlagen. Elf Schlüssel tragen tote Alias-Namen für
ältere Plugin-Stände (`disasmByAddr`, `functionMeta`, `decompileFunction` …). Ein toter
Alias kostet eine 404, ein Schlüssel ohne lebenden Alias ist ein Tool, das nicht
funktionieren kann. Geprüft wird deshalb pro Schlüssel.

**Entfernt, nicht gebaut.** Entscheidung des Nutzers, mit der Begründung, dass ein
Tool, das nie ging, nur ein Baustellenschild ist. Rahmen 1: Starfish ruft keines der
beiden auf. zk-inkjet hat genau einen dokumentierten Aufruf (TRUTH.csv,
CL-TOOL-REC-121): `project_rebase` mit `dry_run=true`, der an der Bridge-Sperre endete
und das Plugin nie erreichte; die Analyse dort kam ohnehin zu dem Schluss, dass ein
Rebase das Basisproblem nicht löst (Move Block in der GUI).

Mit raus: Client-Methoden samt Transaktionshelfern, Whitelist- und Kandidaten-
einträge, HTTP-Routen, vier Schemata, `features/project.py`,
`GHIDRA_MCP_ENABLE_PROJECT_REBASE`, die Mutationsart `bytes` in `list_mutations`
(konnte nicht mehr auftreten, die Beschreibung versprach sie trotzdem), Stubs, Tests,
Doku. `docs/api.md` und der OpenAPI-Snapshot sind neu erzeugt und verlieren nur die
beiden Endpunkte.

**Stub-Durchgang:** ein weiterer Stub bildete eine Methode nach, die kein Client hat —
`list_strings_compact` im Golden-Stub, derselbe Fall wie der in `b194726` behobene im
Contract-Stub. Umbenannt auf `list_strings`. Dabei stand in `docs/api.md` noch der
Fallback über `list_strings_compact`, den es seit `b194726` nicht mehr gibt.

**Abnahme:**

    Routen-Test           vorher rot (6 Schlüssel), jetzt grün
    tools/list (stdio)    34 Tools, kein write_bytes, kein project_rebase
    Schema-Sockel         8 691 -> 8 307 Token, Decke 8 700 -> 8 400
    Suite                 562 grün, 11 übersprungen, 3 rot (s. u.)

**Drei rote Plan-Tests, nicht aus 8b.** Am unveränderten `HEAD` ebenso rot.
`test_agent_metadata_files_exist_and_valid` prüft einen Ablaufzeitstempel und ist
seit vor `583ef6c` rot; die beiden anderen, weil `STAGE-8` und `IMAGE-BASE-STALE` in
der TODO stehen, aber nicht in `state.json`. Der Stand-Eintrag nach Stufe 7 nannte
540 grüne Tests — gezählt über Unterverzeichnisse, die `bridge/tests/plan` nicht
enthielten. Genau davor warnt `scripts/run_tests.sh`; ich habe es in dieser Stufe
zunächst genauso gemacht.

**Nebenbefund, nicht behoben:** der Client wird pro Tool-Aufruf neu gebaut, der
Resolver-Cache überlebt also keinen Aufruf. Bei `FUNC_BY_ADDR` steht der tote Alias
`function_by_addr` an erster Stelle; jeder Aufruf kostet damit eine 404 vorweg.
`GET_XREFS_TO` iteriert seine Kandidaten direkt und beginnt ebenfalls mit dem toten.

## Stufe 8c — Vorfrage beantwortet (2026-10-09)

**Ja: Ghidra legt Referenzen in nicht gemapptes MMIO an.** Gemessen an
`FN_USBD_INIT_PHY_CEP` (0x002AF9C0) über `/xrefs_from` für jede Instruktion. Einziger
Block ist `flash` 0x00200000–0x0047522B; trotzdem trägt `ldr r0,[r0,#0x214]` die
Referenz `b0000214 [READ]`, `str r0,[r1,#0x214]` `[WRITE]`. Die Referenz hängt an
der Lade-/Speicherinstruktion, nicht am `mov`. Positivkontrolle: dieselbe Abfrage
liefert an den Pool-Ladestellen die gewöhnlichen Datenreferenzen.

Über die Funktion: 28 Referenzen außerhalb des Bilds — MMIO und die RAM-Zugriffe über
Pool-Zeiger (0x8190+0x10e…, 0x82B0+4), die der Regexpfad gar nicht platziert.

**Gegenprobe gegen `mmio._collect_operations` (heutiger Stand):** 11 Lade-/Speicher-
befehle lösen beide auf. 6 stimmen überein, **5 widersprechen sich, und in allen 5
liegt der Regex falsch.** Er hält die Basis aus dem letzten `mov rX,#0xb0000000`, auch
wenn das Register danach aus dem Pool neu geladen wurde:

    0x2afa3c  ldr r0,[r0,#0x0]   regex b0000000   ghidra b1008704   (ldr r0,[0x2afb40] = 0xb1008704)
    0x2afa6c  str r0,[r1,#0x4]   regex b0000004   ghidra 000082b4   (ldr r1,[0x2afb48] = 0x000082b0)
    0x2afa90  str r0,[r1,#0x4]   regex b0000004   ghidra 000082b4
    0x2afad0  str r0,[r1,#0x0]   regex b0000000   ghidra b1008704   (ldr r1,[0x2afb40])
    0x2afadc  str r0,[r1,#0x58]  regex b0000058   ghidra b1008058

Ghidra deckt sich mit dem Kommentar im Programm („USBD_BA+0x704 (USB_PHY_CTL)",
„USBD_BA+0x58 (CEP_END_ADDR)"). `mmio_annotate_compact` meldet an dieser Funktion also
heute fünf erfundene Registeradressen — derselbe Befundtyp wie die Stack-Offsets vor
`a807184`. Dazu 13 Zugriffe, die der Regex nicht platziert und Ghidra auflöst
(darunter `0x2afae8` → `b1008058`, die Ladestelle über 0x002AFB4C aus Stufe 2).

**Folge für den Plan:** `refs` reicht für MMIO-Adressen. Die im Plan erwogene
Basis-Auflösung „aus Skalaren statt aus Text" ist nicht nötig, eine Speicherkarte mit
MMIO-Blöcken auch nicht. Die `OR`/`AND`/`TOGGLE`-Zählung des Tools betrifft Werte,
nicht Adressen, und kommt weiter aus Mnemonic und Operanden. Abnahmekriterium 2 („dieselbe Menge
wie vorher") ist damit vorab beantwortet: es wird **nicht** dieselbe sein, und die
fünf Abweichungen oben sind belegte Korrekturen.

Offen: ob die geöffnete Instanz (`archive/…/zk-inkjet-1225`) die eingefrorene
Referenzkopie ist. Die Sonde hat nur gelesen.

## Stufe 8c — Disassemblat als Struktur (Commits `2b74f7c`, `f870d55`)

Plugin: `/disassembleAt`, `/disassemble_function` und `/disassemble` nehmen
`fmt=json`; ohne bleibt es Text (Rahmen 1). `/disassemble` musste mit, weil die
Bridge `DISASSEMBLE` zuerst dorthin auflöst. Pro Instruktion `address`, `bytes`,
`mnemonic`, `text`, `comment`, `flow` (+`conditional`/`computed`/`targets`),
`operands` (Register, Skalare, Adressen aus Ghidras Operandenobjekten) und `refs`
(Ziel, Typ, Operand, `mapped`; bei READ ins Bild das Wort dort).

**Am laufenden Programm geprüft:** Pool-Load `0x2afa38` trägt `word 0xb1008704`, der
folgende Zugriff `refs → 0xb1008704, mapped false`; über 0x002AF9C0 4 Calls, 3
bedingte und 1 unbedingter Sprung, 1 Return über `ldmia …,pc` — alle richtig.
**Zwei Fehler gefunden und behoben, aber noch nicht live bestätigt:** jeder Skalar
wurde mit Vorzeichen gelesen (`#0xb0000000` → `-0x50000000`); jetzt Ghidras eigenes
`isSigned()`, das auch die Listing-Darstellung trägt (`[sp,#-0x4]` bleibt negativ).
Operandentypen hatten ein Leerzeichen am Ende. Die laufende Instanz hat noch den
Build davor; die Bridge hängt an keinem der beiden Felder für Adressen.

**Abnahme:**

1. Stufe-2-Regressionstest: grün, live, mit 33 weiteren Live-Tests.
2. `mmio_annotate_compact` an den Funktionen des Referenzlaufs: **nicht** dieselbe
   Menge, und so angekündigt (Vorfrage). Alle 28 Zugriffe an 0x002AF9C0 = Ghidras
   Referenzen außerhalb des Bilds; fünf Fehladressen korrigiert, 13 RAM-Zugriffe
   über Pool-Zeiger neu, `skipped` 12 → 0 (Pool-Loads waren als „nicht platzierbar"
   gezählt). Live-Test `test_mmio_stale_base_live.py`, gegen den alten Stand rot.
3. In `mmio.py`, `analyze.py`, `strings.py` kein Regex mehr auf Operandentext.
   Übrig, mit Begründung im Docstring: ein Muster auf dem Mnemonic (`mmio`), die
   Prosa von Funktions-Metadaten und Xref-Kontext sowie Escape-Bytes im
   String-Inhalt (`analyze`).
4. Referenzlauf, Bridge vor 8c (`b7f192b`) gegen nach 8c, dasselbe Plugin, beide
   mit Fingerabdruck: **68 260 → 68 109 Bytes (−151)**, 40 Aufrufe, 0 Fehler. Nur
   `string_xrefs_compact` (−16) und `mmio_annotate_compact` (−135) ändern sich.

**Abweichungen außerhalb von MMIO, live alt gegen neu, alle Korrekturen:**
`analyze` an 0x0025B0C4 findet drei bedingte Calls (`BLLT`, `BLEQ`), die der
`BL`-Regex nicht traf, und meldet keinen „String" mehr, der die ersten Bytes eines
`BLLT`-Ziels war (`\x10@-\xe9_`). Die drei übrigen Dossiers sind in Calls, Strings und
Zählungen identisch; das Fenster wächst um 72 Bytes, weil `bytes` jetzt gefüllt ist.
`string_xrefs_compact` 0x00400000: 19 von 20 gleich, beim 20. fällt ein `arg_index`
weg, der aus dem Basisregister einer späteren Instruktion geraten war.

**Testbestand, der Falsches festschrieb:** Ein Literal-Load zählte als READ am
geladenen Wert, `ldrb`/`strh` wurden ignoriert, Stubs lieferten Call-Ziele als Namen
und String-Adressen im Text — Formen, die das Plugin nie erzeugt. Umgeschrieben auf
die gemessenen Formen, `test_mmio_heuristics.py` und
`test_mmio_base_resolution.py` ersetzt.

**Nicht in 8c:** `disasm`, `batch_ops`, `search_function`, `functions` lesen
weiterhin Textzeilen, zerlegen aber keine Operanden. `MMIO-ZERO-TARGET` (bitweise
Operation ohne Immediate als `target 0x0`) ist alt und notiert.

## Stufe 8d — `/functionsInRange` als JSON (Commit `c0d2115`, Plugin 1.3.56)

`fmt=json` liefert `name`, `address`, `size`, `span` und, wo sie etwas aussagen,
`thunk`/`thunk_to`/`chunks`. Die Bridge zerlegt keine Zeile mehr; ein Fehler ist
`UNAVAILABLE` statt einer leeren Liste („keine Funktionen hier").

**Abnahme**, live gegen Plugin 1.3.56, Fingerabdruck geprüft:

- Beide Bereiche des Referenzlaufs und der Bereich um `boot_init`: alter Textweg und
  JSON identisch. `FUNC-CHUNKS-THUNKS` bleibt verifiziert: `boot_init @ 0x00273ee4`
  ist Thunk auf `0x0025b0c4`.
- Ganzes Programm, 1 266 Funktionen: zwei Abweichungen, beide Thunks auf externe
  Funktionen (`thunk_EXT_FUN_0006781e`). Der Textweg meldete `0xEXTERNAL:00000001`,
  was das Hex-Muster des Antwortschemas verletzt — **jede Abfrage über einen Bereich
  mit einem davon scheiterte bisher komplett**, nur liegt keiner in den
  Referenzbereichen. Die erste JSON-Fassung machte `0x00000001` daraus, eine
  erfundene Adresse; jetzt `is_thunk` ohne `thunk_to`. Die Ganzprogramm-Abfrage
  besteht das Schema.
- Referenzlauf: 68 109 → 68 109 Bytes, 40 Aufrufe, 0 Fehler.

**Nachtrag zu 8c, live bestätigt mit 1.3.56:** alle 1 147 Skalare der vier
Referenzfunktionen stimmen mit Ghidras Operandentext überein, Vorzeichen
eingeschlossen; Operandentypen ohne Leerzeichen.

**Nebenbei:** Der Routen-Test sah `/plugin_version` (`e49ea83`, direkt per
`createContext` registriert) nicht — die Zahl 51 stimmte nur zufällig. Er zählt jetzt
beide Registrierungsarten (52). `scripts/build_local.sh` las noch `${revision}` aus
der `pom.xml` und hätte Version `unknown` gebaut; jetzt `plugin_version.sh` und
dieselbe Filterung wie Maven.

## Stufe 8 — Stand

    8a  Loopback-Bind                      abgenommen (62498c6)
    8b  Phantom-Tools entfernt             abgenommen (d2ae916), 36 -> 34 Tools
    8c  Disassemblat als Struktur          abgenommen (2b74f7c, f870d55)
    8d  /functionsInRange als JSON         abgenommen (c0d2115)
    Referenzlauf      68 260 -> 68 109 Bytes, 0 Fehler
    Schema-Sockel     8 691 -> 8 307 Token, Decke 8 400
    Tests             565 grün, 11 übersprungen (Bridge auf :8000), Plan-Tests grün
    Plugin            1.3.56

Gefundene Fehler, die wie Aussagen über die Firmware aussahen: fünf erfundene
MMIO-Registeradressen, ein „String" aus Maschinencode, drei verschwiegene bedingte
Calls, ein geratenes Argumentregister, eine Funktionsliste, die an zwei externen
Thunks komplett scheiterte. Keiner davon kam aus einem Test der Suite; alle aus dem
Vergleich alt gegen neu am laufenden Programm.


---

# Sitzungsabschluss (2026-10-10)

Sitzung vom 2026-10-09/10, Commits `db7d982..bf9d3c2` (27) in diesem Repo, dazu `476d1b1`
im ZK-Inkjet-Projekt. Alles gepusht. Plugin 1.3.60 installiert und live geprüft.

## Was gemacht wurde

| Thema | Commits | Ergebnis |
|---|---|---|
| Stufe 8a Loopback | `db7d982`, `62498c6` | Plugin nur auf `127.0.0.1`, per Skript mit Positivkontrolle abgenommen |
| Stufe 8b Phantom-Tools | `d2ae916` | `write_bytes`/`project_rebase` entfernt; Routen-Test gegen das Plugin |
| Plan-Tests | `7cc9917` | abgelaufener Lease, fehlende IDs; Suite wieder vollständig grün |
| Stufe 8c Struktur | `b7f192b`, `2b74f7c`, `f870d55`, `2f37e87` | `fmt=json`-Disassemblat; mmio/analyze/strings lesen Ghidras Referenzen |
| Stufe 8d Funktionsliste | `c0d2115`, `f453e30` | `/functionsInRange` als JSON; externe Thunks ohne erfundene Adresse |
| Versionierung | `e49ea83` | aus einem Parallel-Chat; Routen-Test und `build_local.sh` nachgezogen |
| R.12 `apply_label` | `6b06bcf`, `d7e158b`, `8d11a26` | Labels auch an MMIO; Skript dubliziert nicht mehr (zk: CL-TOOL-REC-122) |
| `DEAD-ALIAS-FIRST` | `ce0abaf` | 15 tote Aliase raus; jede Anfrage trifft eine echte Route |
| `MMIO-ZERO-TARGET` | `2d4db72` | bitweise Operation ohne Wert: `target null`, kein `address_abs` |
| Antwortschema-Fehler | `704b5a5` | 52 Stellen `INTERNAL` statt `INVALID_REQUEST` |
| `JT-PRENAME-PARSE` | `d873890` | gemeinsamer Prosa-Parser; `verify.name` erstmals echt |
| `find_in_function` | `b3ef40b` | `fmt="text"`; JSON-`address` und `truncated` korrigiert |
| `/renameData` | `5174f5a`, `3b15f0d` | meldet, was passiert ist; No-op ohne Transaktion |
| `IMAGE-BASE-STALE` | `b3bad8d` | `project_info.layout_notes` |
| `ANALYZE-POOL-CONSTANTS` | `4d78d89` | Abschnitt `constants` im Default-Dossier |
| `DOC-DEFAULT-DRIFT` | `514b287` | Test Beschreibung gegen Schema/Code |
| R.22 Korrektheit | `6d83916`, `bf9d3c2` | unbekannter Datentyp ist ein Fehler statt still `int` |

## Zahlen

    Referenzlauf (Default)   68 260 (vor 8c) -> 59 804 Bytes, 0 Fehler, Fingerabdruck geprüft
                             find_in_function −9 713; constants +1 205; layout_notes +335
    Schema-Sockel            8 691 -> 8 481 Token (35 Tools, Decke 8 500)
    Tests                    565 -> 601 grün, 11 übersprungen (keine Bridge auf :8000)
    Plugin                   unversioniert -> 1.3.60, Routen 51 -> 53

## Der rote Faden, fortgesetzt

Derselbe Befundtyp wie im August, diesmal an der Naht: **eine Antwort, die aussieht wie
eine Aussage über die Firmware oder über das eigene Tun, und keine ist.** Fünf erfundene
MMIO-Registeradressen; ein „String" aus Maschinencode; `verify.name` immer `null`;
`comment_present` aus einem Feld, das es nicht gibt; „Rename data attempted"; ein
unbekannter Datentyp als `int`; `address: null` bei jedem Treffer; `truncated: true` ohne
Kürzung; eine Funktionsliste, die an zwei externen Thunks komplett scheiterte.

Keiner dieser Fehler kam aus der Suite. Gefunden hat sie der **Vergleich alt gegen neu am
laufenden Programm**, und in fast jedem Fall stand dahinter ein **Stub, der eine Form
lieferte, die das Plugin nie erzeugt** (`name`/`comment`-Felder, Call-Ziele als Namen,
String-Adressen im Text, tote Routen-Aliase). Das ist die wichtigste Lehre dieser Sitzung:
ein Stub beweist nur sich selbst. Die Gegenmittel sind jetzt Tests, die gegen den
Java-Quelltext oder gegen gemessene Antworten prüfen (`test_plugin_routes.py`,
`listing_records.py`, die Prosa-Fixtures), und Live-Tests mit Gegenprobe gegen den alten Stand.

Zweite Lehre, kleiner: **ein Prüfskript braucht dieselbe Prüfung wie der Code.** Das
Loopback-Skript schlug gegen ein korrekt gebundenes Plugin an (IPv4-mapped), der erste
Routen-Test sah `/plugin_version` nicht, die erste Alias-Bereinigung machte Tupel zu Strings,
die erste Schemazählung übersah mehrzeilige Aufrufe. Jedes Mal fiel es auf, weil eine
Zahl nicht zur Inventur passte.

## Arbeitsweise, die getragen hat

- Schreibtests an der eingefrorenen Kopie nur nach Absprache, mit eindeutigem Namen
  (`R12_live_check`, `R58_live_check`, `R60_live_check`), danach Strg+Z in Ghidra und
  Nachweis über `/check_dirty_state` und einen Lesezugriff.
- Plugin-Commits vor dem Build, damit die installierte Version (`/plugin_version`) genau
  einem Commit entspricht.
- Vor jedem Push: Diff und Commit-Messages auf lokale Pfade und LAN-Adressen prüfen. Vor dem
  ersten Push wurde die ungepushte History dafür umgeschrieben (Pfad, LAN-IP).

## Hand-off (2026-10-10)

> **Abgelöst** durch das Hand-off vom 2026-10-11 am Ende dieses Dokuments. Erledigt seither:
> R.23, R.26, R.25, R.24 (Phasen 1 und 2). Unverändert offen: der R.22-Cache, der
> Skript-Adapter, `save_program` mit `program_name: null`, der Nutzen der `jt_*`-Familie,
> `jt_slot_process` live, und die Punkte im ZK-Inkjet-Projekt.

**Vor der nächsten Arbeitssitzung am ZK-Inkjet-Projekt:** die dortige Bridge neu starten,
sonst läuft sie mit altem Code. Plugin 1.3.60 ist installiert; alles ab 1.3.56 genügt der Bridge.

**Offen in diesem Repo**, in dieser Reihenfolge empfohlen:

1. **R.23** `open_program`-Bereitschaft. `ProgramStatusTracker` (IDLE/LOADING/READY) und
   `/api/current_program.json` existieren; erst prüfen, was davon fehlt, dann bauen.
2. **R.26** Schreib-Endpunkte prüfen `domain_file_id` gegen das aktive Programm.
3. **R.25** `/info` zeigt, ob Schreiben freigegeben ist.
4. **R.22 Cache** nur nach einer Messung, die ihn rechtfertigt.
5. **Skript-Adapter** (eigene Stufe, Entscheidung offen): ein `run_script`-Tool, das nur
   geprüfte, committete Skripte aus einem Repo-Ordner in einer Transaktion ausführt.
6. Kleinkram: `save_program` meldet `program_name: null` ohne Änderungen; der Nutzen der
   `jt_*`-Familie (914 Sockel-Token) ist ungemessen; `jt_slot_process` wurde nie live
   geschrieben; die `/renameData`-No-op-Prüfung ist bestätigt, `apply_label` und
   `/createLabel` auch.

**Offen im ZK-Inkjet-Projekt** (nicht hier zu entscheiden): Block `flash` auf die
Linkbasis 0x00058000 verschieben (CL-TOOL-REC-121; dort liegt ein ungetracktes
`rebase_app_to_58000.py`), die 96 Label-Dubletten bereinigen (CL-TOOL-REC-122).



---

# R.24 — Bestandsaufnahme der Plugin-Antworten (2026-10-10)

Grundlage: alle 53 Routen im Java-Quelltext, jede Client-Methode und die Feature-Module,
die Plugin-Text selbst lesen; dazu 245 lesende Live-Proben mit Plugin 1.3.63 (gültige,
ungültige und nicht gemappte Eingaben je Route, Programm danach unverändert). Die
schwersten Befunde sind im Code nachgeprüft (markiert mit ✓).

## Plugin: wie Fehler aussehen

**Jeder Fehler auf Handler-Ebene kommt mit HTTP 200.** Echte Fehlerstatus gibt es nur
im Dispatcher: 425/503 (kein Werkzeug), 409 (R.26), und das 404 des JDK-Servers für
unbekannte Pfade (HTML; Kontexte passen per Präfix, `/functionsX` landet bei `/functions`).
Eine Ausnahme im Handler wird `{"error":"Internal error: …"}` — mit 200, auch auf
Text-Routen.

Sieben Fehlerformen nebeneinander:

| # | Form | Routen |
|---|---|---|
| B | `{"error","status":"error"}` als `application/json` | 9 (`goto`, `open_program`, `save_program`, `createLabel`, …; Disassemblat-Routen nur mit `fmt=json`) |
| C | dasselbe JSON als `text/plain` | 11 (`read_dword`, `read_bytes`, `read_cstring`, `data_window`, `readBytes`, `project_info`, `project_files`, Textmodi von `functionsInRange`/`disassembleAt`) |
| D | Seiten-Umschlag `{"items":[],"has_more":false,"error":…}`, kein `status` | 6 (`imports`, `exports`, `xrefs_to`, `strings`, `searchFunctions`, `searchScalars` — letzteres auch Teilseite *mit* `error`) |
| E | `{"ok":false,"error":…}` | 5 Datentyp-Routen |
| F | voller Datensatz mit `"status":"error"` | `createLabel` (Anlegen gescheitert), `open_program` |
| G | Prosa mit festem Präfix (`ERROR:`, `Failed to set function prototype:`) | 2 |
| H | **freie Prosa ohne Marker** | **26** — `No function found at …`, `Decompilation failed`, `Error getting function: …`, `Failed to set comment`, `Rename failed`, `No program loaded`, … |

Eine ungültige Adresse wird nicht geprüft: `getAddress` liefert `null`, und der Text der
Java-NullPointerException wird zur Antwort (`Cannot invoke "…Address.addNoWrap(long)"
because "addr" is null`, live an `read_dword`, `read_bytes`, `get_function_by_address`,
`decompile_function`, `disassemble`).

## Plugin: falsche Erfolgsmeldungen und Nebenwirkungen

1. ✓ `/renameVariable` meldet `Variable renamed` und committet, auch wenn
   `updateDBVariable` warf: `finally { successFlag.set(program.endTransaction(tx, true)); }`.
2. ✓ `/deleteDataType` ignoriert den Rückgabewert von `dtm.remove(...)`; `kind` wird ignoriert,
   jeder Nicht-Union heißt `"structure"`.
3. ✓ `/set_function_prototype` committet die Plate-Notiz `Setting prototype: …` in eigener
   Transaktion vor dem Parsen — auch wenn das Setzen scheitert.
4. ✓ Leere Parameterwerte fallen beim Parsen weg (`kv.length == 2`): ein Kommentar lässt sich
   nicht löschen, `comment=` wird zu `Failed to set comment`.
5. `/set_local_variable_type`: Erfolg und Fehler unterscheiden sich nur in der letzten Zeile;
   ohne `new_type` NullPointerException → 200 `Internal error`.
6. `/rename_function_by_address` benennt bei einer Adresse mitten in der Funktion die
   umgebende um und meldet Erfolg.
7. `/function_xrefs`: unbekannte Funktion und Funktion ohne Referenzen geben denselben Text.
8. `paginateList`-Routen geben `""` für „leer" und „hinter dem Ende", ohne `has_more`.
9. `/disassembleAt` beginnt bei einer Nicht-Instruktion still bei der nächsten.
10. `/readBytes`: `length=0` liest ein Byte; kurze Lesungen und die 4096-Kappung ohne Marker.
11. Ungültige Cursor werden still ignoriert, die Seite beginnt neu (`searchFunctions`, `searchScalars`).

## Bridge: wie sie Fehler erkennt

- HTTP ≥ 400 und Transportfehler → `RequestError`.
- Ein JSON-Objekt mit Schlüssel `error` → `RequestError(200)`, auch eine Teilseite mit Warnung
  (die Treffer gehen verloren); die nachgelagerten `payload.get("error")`-Prüfungen sind dadurch tot.
- `ERROR:` als erste Zeile → Fehler. Das Plugin sendet das an keiner Route, die die Bridge ruft.
- Alles andere ist Daten. Prosa-Fehler erkennt nur `_confirmed` (WRITE-ANSWER-TRUTHFUL).
- ✓ Der Resolver weicht bei **jedem** Fehler auf den nächsten Kandidaten aus und fragt dabei
  den gecachten noch einmal: **ein fehlgeschlagener Aufruf geht zweimal raus, POST-Schreibaufrufe
  eingeschlossen** (ein gelandetes Anlegen nach Timeout meldet dann „already exists").

## Bridge: wo ein Fehler als Befund durchgeht (Rangfolge)

1. ✓ `jt_slot_check`/`jt_scan`: der ARM/Thumb-Adapter hält jedes Ziel für eine Funktion —
   `disassemble_function` liefert die Prosa „No function found …" als nicht leere Liste.
2. ✓ `decompile_function` prüft nur `startswith("ERROR")`: „Decompilation failed",
   „No function found …", „Error decompiling function: …" gehen als C-Code in
   `analyze_function_complete` (Snippet, `error: None`) und `find_in_function`.
3. ✓ `search_functions`: bei jedem Fehler Fallback auf `/functions?filter=…` — das Plugin kennt
   `filter` nicht und liefert **alle** Funktionen als Treffer, 300 s gecacht.
4. `search_scalars`: Fehler und die Inspektionsgrenze werden zu einem gültigen leeren Ergebnis
   (`_LIMIT_ERROR_MARKERS` passt nicht zur Meldung des Plugins).
5. `read_bytes`/`read_words`: Transport- oder Plugin-Fehler werden als „nicht gemappt" gemeldet —
   eine Aussage über die Firmware.
6. `disassemble_at`: jeder Fehler wird `[]` und bekommt die Notiz „keine Instruktionen definiert".
7. Fehler-Leerlisten werden 300 s gecacht (strings, imports, exports, xrefs).
8. `get_xrefs_to`: Fehler ist `[]` wie „keine Referenzen"; `has_more` geht verloren.
9. Strikte Client-Schemas: ein zusätzliches Feld vom Plugin macht xrefs/strings/imports/exports
   still leer.
10. ✓ `analyze`: Callee-Namen immer `None` (liest `name`, das Plugin sendet `Function`).
11. ✓ `strings_compact`/`search_strings`: `refs` immer 0 (aus Feldern, die das Plugin nicht sendet).
12. „Error getting function: …" wird zu einem gültigen Metadaten-Dict (enthält einen Doppelpunkt).
13. Falsche Gründe: leere/abgelehnte Antworten heißen „Plugin zu alt"; Plugin-Ablehnungen
    (Datentyp existiert, Speichern nicht erlaubt) heißen Transportfehler/`UNAVAILABLE`.


---

# Sitzungsabschluss (2026-10-11)

Sitzung vom 2026-10-10/11, Commits `ea2700a..cd3a1bd` (19) plus dieser Abschluss. Alles
gepusht. Plugin 1.3.65 (API 2) installiert und live geprüft.

## Was gemacht wurde

| Thema | Commits | Ergebnis |
|---|---|---|
| R.23 Programmzustand | `ea2700a`, `11a6a13`, `6a7aff9` | Zustand je Abfrage aus `isAnalyzing()`; kein erzwungenes READY nach 5 min; `select_program` wartet bis 10 s |
| R.26 Schreibziel | `c608a50`, `7970837`, `d0cb665` | Schreibzugriffe gegen das aktive Programm geprüft, in der Bridge vor dem Senden und im Plugin am Handler (409) |
| `WRITE-ANSWER-TRUTHFUL` | `b5d961a` | „Failed to rename function" galt als Erfolg |
| R.25 Read-only | `31e4442`, `9814892` | `writes_enabled`/`writes_note` in `project_info` und Health; eine Formulierung; `save_program` gesperrt |
| R.24 Bestandsaufnahme | `825fe40` | 53 Routen, alle Client-Methoden, 245 Live-Proben |
| R.24 Phase 1 (Bridge) | `a6379fa`, `05361f7`, `21ba8ab`, `27b39fc` | Resolver sendet einmal; kein Alle-Funktionen-Fallback; Fehler sind Fehler statt leer; Jump-Table-Adapter prüfen den Funktionsbeginn; Scalar-Grenze als `truncated` |
| R.24 Phase 2 (API 2) | `fc8da25`, `f587462`, `a5c56e4`, `cd3a1bd` | jeder Fehler mit HTTP-Status und einer JSON-Form; Bridge verlangt API 2 und trennt „nichts da" von „gescheitert" |

## Zahlen

    Referenzlauf (Default)   59 804 -> 60 171 Bytes, 40/40 ohne Fehler, Fingerabdruck geprüft
    Schema-Sockel            8 481 -> 8 494 Token (35 Tools, Decke 8 500)
    Tests                    601 -> 697 grün, 11 übersprungen (keine Bridge auf :8000)
    Live-Tests               39 -> 59 grün (Plugin 1.3.65)
    Plugin                   1.3.60 -> 1.3.65, Antwortkonvention API 2

## Der rote Faden, ein drittes Mal

Wieder derselbe Befundtyp, diesmal eine Ebene tiefer, bei der Frage, woran man einen Fehler
überhaupt erkennt. **Jeder Fehler des Plugins kam mit HTTP 200**, in sieben Formen, an 26
Routen als Prosa ohne Kennzeichen. Daraus folgte fast alles andere: „Variable renamed",
nachdem das Umbenennen geworfen hatte; jede Jump-Table-Adresse als Funktion, weil
„No function found …" eine nicht leere Liste ist; eine gescheiterte Funktionssuche als
Liste aller Funktionen, 300 s gecacht; Decompiler-Fehlertext als C-Code; jeder Lesefehler
als „Speicher nicht gemappt"; ein Resolver, der jeden Fehlschlag zweimal schickte, Schreiben
eingeschlossen. Und wieder hielten Stubs es verdeckt: `OK` und `ERROR: …` als Antworten,
die das Plugin nie sendet, „Scan limit exceeded" mit HTTP 413, Funktions-Datensätze mit
`name`/`comment`.

Die Abhilfe ist diesmal strukturell statt Stelle für Stelle: eine Konvention mit echten
Status (API 2), ein Ort im Client, der sie anwendet, und die Regel, dass ein Fehler nie
zu einem leeren Ergebnis wird. Ein Plugin ohne die Konvention wird abgelehnt statt erraten
(Entscheidung des Nutzers, keine Rückwärtskompatibilität). Gegen das Wiederkehren: Tests
gegen den Java-Quelltext (keine Fehlerprosa, jeder Writer setzt den Header) und ein
Test-Transport (`plugin_http.py`), der wie das Plugin antwortet.

## Arbeitsweise, die getragen hat

- Bestandsaufnahme vor dem Umbau: zwei Agents (Plugin-Seite, Bridge-Seite) parallel zu
  eigenen Live-Proben; die schwersten Behauptungen im Code nachgeprüft, bevor darauf
  gebaut wurde. Alle geprüften stimmten.
- Phasen nach Abhängigkeit: erst, was unabhängig von der Konvention falsch war (nur Bridge,
  kein Reinstall), dann die Konvention mit einem Reinstall.
- Live-Tests nur lesend oder als Dry-Run; ein Schreibtest an der eingefrorenen Kopie war in
  dieser Sitzung nicht nötig. Der neue Live-Test fand eine übersehene ungeprüfte Adresse,
  die keine Unit-Prüfung gesehen hatte.
- Panne: `scripts/reference_run.py` schreibt per Default in die eingecheckte Baseline
  `baseline/reference_run.jsonl` und hat sie überschrieben; wiederhergestellt, danach mit
  `--usage-log` in eine Scratch-Datei. Siehe Hand-off.

## Hand-off (2026-10-11)

**Vor der nächsten Arbeit am ZK-Inkjet-Projekt:** die dortige Bridge mit aktuellem Code neu
starten. Ein alter Bridge-Stand versteht die Fehlerstatus von Plugin 1.3.65 nicht. Die lokale,
ignorierte `.env` in diesem Repo setzt `GHIDRA_MCP_ENABLE_WRITES=true`; eine aus diesem
Verzeichnis gestartete Bridge schreibt also, wenn ein Tool `dry_run=false` bekommt.

**Verhaltensänderungen, die Aufrufer merken können:**
- `rename_function`, Prototyp und Variablentyp nur noch am Einsprungpunkt (vorher die
  umgebende Funktion bei einer Adresse mitten im Rumpf).
- `/set_function_prototype` schreibt keine Plate-Notiz „Setting prototype: …" mehr.
- Ein Kommentar mit leerem Text löscht den Kommentar.
- Mehrfach-Schreiber (`mmio_annotate_compact`, `jt_slot_process`) brechen beim ersten
  gescheiterten Schreibzugriff mit dessen Fehler ab, statt nur weniger zu zählen.
- `analyze_function_complete` hat kein `function.comment` mehr (war immer `null`).

**Offen in diesem Repo**, in dieser Reihenfolge empfohlen:

1. ~~**`reference_run.py`-Default**~~ erledigt (`d71cfce`): Beide Referenzskripte schreiben
   per Default nach `runs/` (ignoriert); eine vorhandene Datei unter `baseline/` ersetzen
   sie nur mit `--overwrite-baseline`. Der Lauf mit 60 171 Bytes ist reproduziert und liegt
   als `baseline/reference_run_r24.jsonl` (+ `.summary.json`) vor. Die Reproduktionsbefehle
   der Stufe-0-Ergebnisse oben würden heute abgelehnt, weil die Datei existiert; gewollt.
2. **R.24 Phase 3:** Paginierung ohne `has_more` (`""` für leer und hinter dem Ende), still
   ignorierte Cursor, `readBytes length=0`, Wahrheitswerte als Strings, `check_dirty_state`
   ohne Programm `ok`, `/disassembleAt` an Nicht-Instruktionen. Teils inkompatibel.
3. **R.29** Zeichenbudget für `analyze_function_complete`: braucht einen Parameter, der
   Schema-Sockel steht bei 8 494 von 8 500 -- erst anderswo kürzen.
4. **R.22-Cache** nur nach einer Messung.
5. **Skript-Adapter** (Entscheidung offen).
6. Kleinkram: `save_program` mit `program_name: null` ohne Änderungen; Nutzen der
   `jt_*`-Familie ungemessen; `jt_slot_process` nie live geschrieben;
   `WRITE-ANSWER-TRUTHFUL` und der Übergang `LOADING`→`READY` nur im Stub geprüft (beides
   bräuchte einen Schreibtest bzw. eine laufende Analyse).

**Offen im ZK-Inkjet-Projekt** (unverändert, nicht hier zu entscheiden): Block `flash` auf
0x00058000 verschieben (CL-TOOL-REC-121), die 96 Label-Dubletten bereinigen (CL-TOOL-REC-122).

## Bestandsaufnahme R.24 Phase 3 (2026-10-11)

Zwei Agents parallel (Plugin mit lesenden Live-Proben gegen 1.3.65, Bridge im Code); die
tragenden Befunde nachgeprüft, live und im Code. Alle stimmten.

**Versionsprüfung ohne Obergrenze.** Die Bridge lehnt nur `api < 2` ab
(`client.py:497`). Ein Plugin mit API 3 würde angenommen und nach API-2-Regeln gelesen.
Daran hängt Punkt 4: sendet das Plugin echte Booleans, meldet die Bridge (`== "true"`,
`tools.py:872/912`) still `changed:false` und `saved:false`, und das Mutations-Ledger würde
nie geleert.

| # | Punkt | Plugin | Bridge | falsch beim Modell? |
|---|---|---|---|---|
| 1 | `paginateList` `""` für leer und hinter dem Ende | 9 Textrouten | nutzt keine (nicht auf der Whitelist) | nein |
| 2 | ungültiger/fremder Cursor | fällt still auf `offset` zurück | reicht durch, sendet `offset=0` | ja, über HTTP-Routen und `collect` |
| 3 | `readBytes length=0`, kurze Lesung | 0→1 Byte, >4096 still gekappt, kein Marker | erkennt kurze Lesungen selbst; `collect` prüft `length` nicht | gering (`collect`) |
| 4 | Wahrheitswerte als Strings | `"changed":"false"` | `== "true"` | heute nicht; nach Plugin-Fix still falsch |
| 5 | `check_dirty_state` ohne Programm `ok` | Zweig praktisch tot (Dispatcher antwortet 425) | behandelt 425 | nein |
| 6 | `/disassembleAt` an Nicht-Instruktion | springt still weiter (an `0x10`: 2 MB) | `coverage` rechnet den Start nach | nein, außer Kontextfenster |

Nebenbei, live und nachgeprüft: `string_xrefs_compact.count` ist die gekappte Länge;
`analyze_function_complete` meldet gekappte inbound-Zahlen, `truncated` ignoriert Xrefs;
`search_functions(context_lines)` macht aus einem Fehler ein leeres Disassemblat. Im Plugin:
ungültige Ganzzahlen werden still zum Default; `searchScalars` am Inspektionslimit mit
`has_more:false`; `/xrefs_from` an ungemappter Adresse 200 leer. Stubs abweichend: Cursor
`"3"` statt `v1.…`, `readBytes` 0 → leer, `searchFunctions` ohne Programm 200 mit `error`.

Die Kontextfenster der Scalar- und Funktionssuche beginnen bei Treffer minus n·4 und brauchen
das Weiterlaufen von `/disassembleAt`; deshalb meldet es künftig den echten Start, statt mit
404 abzulehnen.

**Entscheidungen des Nutzers:** API 3 mit exakter Prüfung; `/disassembleAt` läuft weiter und
meldet; `paginateList`-Routen bleiben. Aufteilung in Teil A (nur Bridge, zuerst) und Teil B
(Plugin, ein Reinstall) in `.plan/TODO.md` unter R.24-PHASE3.

### Teil A erledigt (2026-10-11, nur Bridge)

Sieben Commits, `3bc4e63` bis `4d57f8e`:

- `changed`/`can_save`/`saved` werden als `"true"`/`true` und `"false"`/`false` gelesen,
  jeder andere Wert ist ein Fehler. Damit kann das Plugin in Teil B auf echte Booleans gehen.
- Gekappte Referenzlisten sagen es: Es wird eins mehr als das Limit angefragt.
  `string_xrefs_compact` bekommt `truncated` (`count` = gezeigte Aufrufer), die
  Xref-Zusammenfassung von `analyze_function_complete` `inbound_truncated`/`outbound_truncated`,
  `features.notes` nennen das Limit, `meta.truncated` berücksichtigt die Xrefs. Live: Der
  String an 0x00400000 hat genau 20 Referenzen, beim Default-Limit 20; die alte Antwort war von
  einer gekappten nicht zu unterscheiden.
- `search_functions(context_lines)`: Ein Fehler beim Kontextfenster bleibt ein Fehler.
- `collect` hält die Grenzen der eigenen Tools (`length`, `count`, `context_lines`).
- `search_scalars_with_context` gibt keinen Cursor mehr aus, den es nicht annimmt; der
  Docstring nannte ein `page`, das es nicht gibt. Schema-Sockel 8 494 → 8 485.
- `reference_run.py`: Der Fingerabdruck prüft den HTTP-Status.
- Stubs wie das Plugin: Cursor `v1.…` (Helfer `plugin_cursor` in `plugin_http.py`, verankert an
  einem Live-Cursor), `readBytes` mindestens 1 Byte, ohne Programm 425 `NOT_READY`.

Live: 59/59 grün, Referenzlauf 40/40 ohne Fehler, 60 171 → 60 193 Bytes (die neuen Felder),
Programm danach unverändert (`check_dirty_state`). Offen bleibt Teil B. Im selben Zuge nicht
angefasst: `analyze_function_complete.strings` ist ebenfalls bei `limit` gekappt, zeigt aber
`limit` mit an.

### Teil B erledigt (2026-10-11, API 3, Plugin 1.3.66)

Ein Commit, `6a8b50b`, Plugin und Bridge zusammen; installiert und live geprüft.

- Plugin: `changed`/`can_save`/`saved` als JSON-Booleans (`save_program` ohne Änderungen
  nennt jetzt das Programm); ein Cursor, den die Route nicht ausgegeben hat, eine
  Nicht-Zahl, `readBytes length` außerhalb 1..4096 und `disassembleAt count` außerhalb
  1..128 sind 400; `/disassembleAt` und `/xrefs_from` an ungemappter Adresse sind
  UNMAPPED; `/disassembleAt?fmt=json` meldet `requested`/`start`; `check_dirty_state` ohne
  Programm NOT_READY; ein abgebrochener Scalar-Suchlauf sagt `truncated`/`reason` statt
  `error`; Adressen außerhalb des Default-Raums behalten `SPACE:offset`, `/xrefs_to`
  überspringt Nicht-Speicher-Quellen („0xEntry Point").
- Bridge: verlangt genau API 3 (`PLUGIN_TOO_OLD` darunter, `PLUGIN_TOO_NEW` darüber),
  Flags nur als Booleans, ein 200 mit `error` ist immer ein Fehler, `disassemble_at` nennt
  UNMAPPED als solches. Ein Quelltext-Test hält `API_LEVEL` auf `REQUIRED_PLUGIN_API`.
- Kurze Lesungen ohne eigenen Header: Seit Längen außerhalb 1..4096 ein 400 sind, heißt
  weniger Bytes eindeutig, dass der Block endet; das erkennt die Bridge schon.

Live mit 1.3.66: 71/71 (12 neue API-3-Proben, lesend), Referenzlauf 40/40, 60 193 Bytes,
Programm unverändert. Über MCP: `disassemble_at 0x10` meldet „No memory is mapped" statt
einer Auflistung ab 0x00200000; `search_imports` liefert `EXTERNAL:00000001`.


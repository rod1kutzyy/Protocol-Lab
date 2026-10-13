# AGENTS.md — Protocol Lab

> Instructions for AI coding agents and contributors working in this repository.
> Applies to the entire repository unless a more specific `AGENTS.md` exists in a subdirectory.

## 1. Product mission and scope

Protocol Lab is an **offline-first, local web application** for studying undocumented, unencrypted binary device protocols over **TCP/IPv4**. An engineer imports PCAP/PCAPNG captures and an action log, explores reconstructed TCP byte streams, defines and revises protocol interpretations, validates them against a corpus, and exports a reproducible research project.

Build the **R1–R6 mandatory workflow** before optional features. The initial scope explicitly excludes AI assistance, IPv6, live capture, decryption, compressed-payload decoding, and full protocol state-machine reconstruction. Do not implement those features unless the task explicitly changes scope.

The authoritative product requirements are the hackathon case and the project's implementation roadmap. When these documents are available under `docs/`, read them before changing core behavior. Do not substitute demo-specific assumptions for protocol analysis.

### Mandatory outcomes (R1–R6)

| Requirement | Acceptance intent |
| --- | --- |
| **R1 — Original exchange** | Import PCAP/PCAPNG, distinguish actual TCP connections and directions, reconstruct application bytes, and navigate from results to exact source packets and byte ranges. Explicitly diagnose gaps and ambiguities. |
| **R2 — Investigation** | Inspect raw bytes, compare examples and parameters, search for patterns, and associate exchanges with action-log entries. |
| **R3 — Interpretations** | Create/edit a machine-executable protocol model (framing + fields), apply the same model across multiple examples, and distinguish parsed facts from hypotheses. |
| **R4 — Validation** | Validate a selected corpus, report failures, unknown/ambiguous/uncovered cases, show counterexamples, and rerun after changing rules. |
| **R5 — Portable project** | Preserve original captures, models, settings, observations, source mappings and validation results; reopen and reproduce the project after moving it. |
| **R6 — Reuse and reporting** | Export a human-readable report and a machine-readable model. Provide a documented CLI that uses the same engine as the GUI on new captures. |

## 2. Agreed technology choices

- **Frontend:** React, TypeScript, Vite, Tailwind CSS, shadcn/ui, TanStack Query, Zustand, TanStack Virtual, Monaco Editor.
- **Backend:** Python, FastAPI, Pydantic; asynchronous progress updates via Server-Sent Events (SSE).
- **Packet ingestion:** `dpkt` for PCAP/PCAPNG and packet headers. Use TShark for independent checks on applicable test cases; avoid making it the only source of application-byte provenance.
- **Protocol modeling:** versioned declarative JSON + JSON Schema, validated with Pydantic and compiled to a parser using Construct. Framing is a separate step.
- **Persistence:** **PostgreSQL** for research metadata, models, annotations, and validation runs; content files for captures and derived byte-stream artifacts. Use SQLAlchemy and Alembic if introducing ORM/migrations.
- **Reports:** Markdown templates with Jinja2; JSON for machine-readable models and validation output.
- **Background work:** local worker processes (`multiprocessing` / `ProcessPoolExecutor` or an equivalent already present in the project); expose progress and cancellation, not blocking HTTP requests.
- **Testing:** pytest for Python, Vitest for frontend units, Playwright for end-to-end scenarios; use the actual configured scripts and tools in the repository.
- **Dependency management:** `uv` with its committed lockfile for Python and the project's selected Node package manager with its committed lockfile.

Do not introduce microservices, cloud storage, queues, Redis, Kubernetes, or a remote AI dependency unless an explicit requirement justifies them. The core workflow must work with networking disconnected after dependencies are installed.

## 3. Recommended module boundaries

Follow the **existing repository structure** if it is already established; the tree below is a target for an empty repository, not a mandate to restructure working code.

```text
backend/
  pyproject.toml
  src/protocol_lab/
    api/                # FastAPI routers, request/response schemas, SSE
    capture/            # PCAP/PCAPNG decoding, packet metadata, checksums
    tcp/                # Sessionization, directed-stream reassembly, provenance
    framing/            # Stream -> application-message boundaries
    interpretation/     # Model schema, parsing, field extraction
    validation/         # Corpus execution, diagnostics, counterexamples
    research/           # Action logs, observations, hypotheses, versions
    storage/            # PostgreSQL repositories, files, migrations/adapters
    services/           # Application orchestration and background jobs
    cli/                # Reusable command-line entry points
  tests/
frontend/
  src/
    app/                # Routing and app shell
    features/           # Captures, sessions, hex, diff, models, validation
    shared/             # Typed API client and reusable UI
  package.json
docs/                    # Architecture, contracts, requirements, runbook
scripts/                 # Reproducible setup/run/benchmark commands
tests/fixtures/          # Small safe, deterministic test captures and logs
```

**Dependency direction:** API, CLI, and UI are adapters. They call shared application/core services. Core algorithms must not import FastAPI, React, database session objects, or UI code. GUI and CLI must execute the same framing/parsing/validation logic.

Maintain explicit domain concepts: `Capture`, `Packet`, `Session`, `DirectedStream`, `SourceRange`, `Message`, `InterpretationVersion`, `Observation`, `Hypothesis`, `Corpus`, and `ValidationRun`. Avoid conflating a packet, TCP segment, stream, and application message.

## 4. Non-negotiable data and TCP invariants

1. **Originals are immutable.** Copy captures into managed project storage without rewriting their content; record SHA-256, capture ID, format and relevant import settings. Preserve the original bytes for future verification.
2. **Preserve identity.** A TCP session is a concrete connection instance, *not* merely an IP/port four-tuple. Reused addresses and ports do not silently merge different connections. Re-importing the same capture must not silently duplicate or merge research data.
3. **TCP is a byte stream.** Reassemble each direction by sequence number, handling SYN/FIN sequence-space consumption, out-of-order packets and 32-bit sequence wrap correctly. TCP segment boundaries are not application-message boundaries.
4. **Retransmissions do not duplicate payload.** Identical retransmissions map back to their source packets. Conflicting overlaps must remain diagnosable, with an explicit and reproducible policy rather than a hidden guess.
5. **Never invent bytes.** Missing, truncated, uncertain or ambiguous data are first-class ranges/statuses; never silently fill gaps with zeroes or infer unavailable TCP data as fact. Report uncertain session starts/endpoint roles.
6. **Every derived result is traceable.** Maintain provenance from reconstructed stream offsets and parsed fields back to the capture, original packet(s), packet payload offsets, and byte ranges. Track reconstruction policy/version when relevant.
7. **Anchors survive reframing.** Observations must refer to stable source/stream ranges and the relevant derivation version, not only to a mutable `message_id`. Reframing must not silently reattach an observation to different bytes.
8. **Checksums are policy-driven.** Persist the checksum handling policy and warnings. Do not discard a packet by default solely because a locally captured checksum appears invalid (offloading may be involved).
9. **Partial results are explicit.** One malformed or unsupported session must not block work with other sessions. Unsupported link layers, capture conditions or ambiguous data get clear diagnostics.
10. **Do not overclaim semantics.** A successfully parsed field or a correlation with an action log is not proof of the field's real-world meaning.

## 5. Interpretation and validation rules

- Keep **framing** (where messages begin/end) independent from **field decoding** (what bytes mean).
- Support at least manual boundaries, fixed-size framing, length-field framing (configurable offsets, endianness and length formula), and explicitly configured start/end markers. Unframed leftovers and uncertain boundaries must stay visible.
- A declarative interpretation may include integer width/signedness/endianness, raw byte fields, fixed or computed lengths, count-based arrays, field-dependent alternatives, and checks on constants/ranges/lengths.
- Validate model JSON against a versioned schema. Use safe, bounded operations; never execute arbitrary code from imported models, reports or captures.
- Every model change creates a new immutable interpretation version (or equivalent content-addressed revision). Do not rewrite evidence or mistake results of an older run for current results.
- A validation run records: source capture IDs/hashes, selected corpus and filters, interpretation version, reconstruction/framing settings, engine version, results, and counterexamples.
- Use explicit statuses: `passed`, `failed`, `unknown`, `ambiguous`, `not_applicable`. A summary must account for the **entire selected corpus**, including unframed, incomplete and uncovered data.
- Distinguish **observations**, **rule execution**, and **semantic hypotheses** in the data model and UI. Keep hypothesis rationale, evidence, scope, unknowns and contradictions.
- Do not hard-code parsing results using filenames, action labels or special cases from the evaluation corpus. Rules must generalize to unseen captures within their declared scope.

## 6. PostgreSQL, portable projects and security

**Important:** PostgreSQL is the chosen runtime DB, but a PostgreSQL connection string or an absolute database path **is not a portable project**.

- Store captures and derived files under a project root using relative paths and checksums. Keep the archive format version in `manifest.json`.
- Implement project export/import with a **versioned, consistent database snapshot or PostgreSQL dump**, bundled with captured sources, interpretations, settings, observations and checks. Import/restore into a destination PostgreSQL database and run compatible migrations as necessary. Document the restore process and dependencies.
- Do not require the old database server, old absolute filesystem paths, or a network service outside localhost to open an exported project.
- Keep PostgreSQL runtime files, backups, temporary exports and actual research captures outside version control (see `.gitignore`). Small synthetic test fixtures belong under `tests/fixtures/` and **must be committed** when tests depend on them.
- Never commit `.env`, credentials, private keys, personal traffic or production captures. Maintain a redacted `.env.example` where needed.
- Bind the web interface/API to `127.0.0.1` by default. Validate imported paths and archive members (including `../` traversal), set file/job/resource limits, and avoid logging raw sensitive payloads unnecessarily.
- Schema changes require migrations; destructive migrations or deletion of captured sources require explicit authorization. Do not casually reset a user's existing research database.

## 7. API, performance and UX conventions

- Define typed request/response contracts shared conceptually between backend and frontend. Prefer narrow REST endpoints for captures, sessions, stream byte ranges, source mappings, models, validation runs, projects and exports.
- Stream byte ranges using `(stream_id, offset, length)` instead of serializing entire large captures or reconstructed streams to JSON. Make offsets and inclusivity/exclusivity unambiguous and documented.
- Use TanStack Virtual for large lists and HEX views; TanStack Query for server state and Zustand for local selection/editor state.
- Long operations must expose progress, cancellation and a terminal status. Cancellation must not present partial artifacts as complete; previously imported data should remain browsable.
- Error messages should say **what failed, which source/range was affected, and whether the remaining result is usable**. Never silently truncate inputs or suppress counterexamples.
- Document protective limits; measure runtime and peak memory for supported workloads rather than assuming performance.

## 8. Tests and acceptance gates

A change to a core algorithm is incomplete without focused automated tests. Add or update deterministic fixtures with known expected bytes and source mappings.

**Minimum TCP tests:** normal ordered stream; out-of-order packets; duplicate retransmission; SYN/FIN sequence accounting; sequence wrap; one packet with multiple messages; a message across multiple packets; missing segment; truncated packet; contradictory overlap; absent connection start; reused four-tuple; duplicate capture import; checksum-warning policy; one bad session alongside a good session.

**Minimum interpretation tests:** fixed/length/marker framing; endian/sign handling; variable-size replies; arrays/conditional fields; unknown bytes; malformed lengths; model/schema rejection; new corpus reuse without per-message manual edits.

**Minimum research tests:** evidence-to-source navigation; stale run after model edit; corpus coverage including filtered/uncovered cases; counterexample reproduction; exported project restore in a different path; identical GUI/CLI parsing and diagnostics; action-log clock-offset handling.

**End-to-end demo:**

1. Import a capture and action log, select a real TCP connection and inspect its original bytes.
2. Compare actions with different parameters, annotate an observation and create a hypothesis.
3. Define message framing and a reusable interpretation, then validate it on a chosen corpus.
4. Show a concrete counterexample, revise the model and rerun validation with visible differences.
5. Export a project, move it, restore it on a fresh local setup, and apply the model to a new capture with the CLI.

**Control workload:** Linux x86-64, 4 vCPU, 8 GiB RAM; up to 100 MiB of captures, 250,000 packets, 1,000 TCP connections, 100,000 application messages, and variable replies up to 64 KiB. These numbers are a measurement profile, **not** arbitrary protocol-format limits. Record main operation timings, peak RSS and any resource-limit diagnostics.

## 9. Agent working procedure

When given a task:

1. **Inspect first:** read the relevant code, tests, dependency manifests, `docs/` and nested `AGENTS.md` files. Do not assume scaffolding or commands already exist.
2. **Identify the requirement:** name the affected R1–R6 behavior and its observable acceptance test. Prefer the smallest coherent vertical slice.
3. **Protect invariants:** check raw-byte immutability, packet provenance, versioning, corpus scope, offline behavior and backwards-compatible persistence/API contracts.
4. **Implement incrementally:** keep domain logic independent of HTTP, make APIs explicit and typed, and write tests alongside code. Never use fixture-specific shortcuts.
5. **Verify:** run the relevant existing commands for lint, type checking, unit/integration tests and builds. Inspect `pyproject.toml` and frontend `package.json` before choosing commands. Examples, **only if configured**: `uv sync --frozen`, `uv run pytest`, `npm ci`, `npm run build`, `npx playwright test`.
6. **Document:** update public API/schema descriptions, migration/export instructions, troubleshooting notes, and the R1–R6 acceptance matrix when behavior changes.
7. **Report clearly:** summarize changed files, tests actually run, their results, known risks and anything not verified. Never claim successful tests you did not execute.

Do not perform unrelated refactors; do not overwrite user-generated projects or capture data; do not introduce hidden online dependencies; do not suppress errors merely to make a demo pass. Ask before destructive data operations or material changes to the agreed scope/stack.

## 10. Recommended implementation order

1. Freeze requirements, collect input corpus and design a reproducible demo scenario.
2. Scaffold frontend/backend, API contracts, PostgreSQL persistence and local job infrastructure.
3. Implement source import, hashing and packet indexing.
4. Implement TCP sessionization, stream reconstruction and exact provenance.
5. Build session navigation, HEX/ASCII view, byte diff and action-log linking.
6. Implement framing, versioned JSON interpretations and Construct-backed parsing.
7. Implement corpus validation, counterexamples and stale-result handling.
8. Implement complete portable export/import, Markdown report and reusable CLI.
9. Run robustness, offline, load, migration and end-to-end tests; package a reproducible demonstration.

**Definition of done:** the feature works on authentic or deterministic test PCAPs, preserves source provenance, behaves correctly on ambiguous/incomplete data, has tests and documentation, and does not compromise the reusable offline research workflow.

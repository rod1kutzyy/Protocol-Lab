# Automatic analyzer A2

A2 extends the shared A1 discovery run with bounded structure and action-log
proposals. The `groups`, `events`, and `data_mapping` capabilities are reported
through `/inference/capabilities`; structure adds delimiter candidates to the
existing framing-dependent detector.

Delimiter proposals inspect sampled messages from retained A1 framing candidates.
They check repeated one-byte separators, NUL and CRLF, consistent field counts,
and preserve messages that contradict the common count. Escaping, quoting,
nesting, and NUL padding are not inferred. Group proposals compare short fixed
fields independently per direction, retain repeated keys, and mark singleton
keys unassigned. They do not assign command semantics or mask counters/tokens.

Action logs are frozen with the discovery snapshot: imported source checksum,
parser mapping, clock revision, clock offset, and selected event rows. Discovery
rejects changed log settings and verifies the original log checksum. Event
windows use packet timestamps for the bytes of sampled messages; missing packet
times remain unknown, overlapping windows remain ambiguous, and proximity is
not treated as causation.

Parameter mapping uses explicitly selected event IDs and JSON paths (or explicit
text values), then searches only known ranges in discovery streams. It supports
ASCII, UTF-8, UTF-16LE/BE, standard/URL-safe Base64 over those encodings, decimal
text, and configured integer widths/endian. Equivalent byte representations are
collapsed to one canonical candidate; aliases are not yet listed individually.
UTF-16 with and without explicit BOM, plus canonical Base64 padding are searched.
Unmatched values are unknown rather than contradicted. The detector does not
normalize text, decode arbitrary Base64 fields, infer scales, or search holdout.
Short/common values and a single distinct input remain weak evidence.

Focused tests in `backend/tests/test_inference_engine.py` cover delimiter and
group proposals, frozen event timing outcomes, explicit parameter mapping, and
the existing A1 behavior. PostgreSQL publication of frozen log inputs is
exercised by the standard storage integration suite when its configured test
database is available.

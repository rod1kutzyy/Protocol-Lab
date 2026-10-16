# Automatic analyzer A3

A3 adds bounded cross-message candidates for counters, per-session stable byte
regions, exact copied values, packet-time fields, and relative clocks. The same
frozen typed rules run through the GUI endpoint and the offline CLI evaluator.
Each relational rule carries its framing specification so evaluation does not
rely on a mutable or missing parent run.

Counter search checks unsigned 1/2/4/8-byte fields in configured endianness and
bounded fixed, message-length, or payload-length increments. Stream offsets set
message order; gaps produce `unknown`, and modulo arithmetic is explicit. The
first release scopes transitions to one concrete stream/session and does not
infer field masks or cross-direction counter constraints.

Session-region search proposes 4/8-byte regions stable within observed messages
of each session and varying between at least two sessions. Exact copy proposals
require the same value at configured source/target offsets in the reverse
direction, later according to packet timestamps. Missing packet times are
unknown. Session independence and semantic token meaning are never inferred.

Timestamp search compares signed and unsigned 4/8-byte integer fields in s/ms/us/ns with
packet-time intervals. Unix candidates use one shared offset; relative-clock
candidates compare deltas from each observed stream baseline. Tolerance is
bounded by observed packet-time spread with a 5 ms floor. These candidates are
heuristics for review, not wall-clock proof. Drift fitting,
nonstandard units, and automatic clock-correction edits are not implemented.

The typed evaluator supports frozen framing, counter, timestamp, session-stable
region, and copied-value rules. It records source-backed passed/failed facts and
unknown or not-applicable cases; it does not tune parameters on the target corpus.
Other A2 analytical rules without a frozen framing relation remain non-evaluable.
The A3 tests cover wraparound, timestamp offsets, session variation, relation
execution on a target corpus, and CLI/API contracts.

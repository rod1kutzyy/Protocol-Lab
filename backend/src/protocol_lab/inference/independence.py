"""Conservative overlap detection after rules are frozen, independent of segmentation.

Hashes use TCP sequence-aligned 64-byte blocks and endpoint coordinates. Finding
shared wire bytes prevents a claim of independent recording. Absence is conditional
on known captured bytes; unread/incomplete inputs are explicitly unverified.
"""

import hashlib
from itertools import chain

from protocol_lab.capture.index import WorkCancelled

VERSION = "wire-block-overlap-1"
BLOCK = 64
MOD = 2**32


def recording_overlap(discovery, target, budget, cancelled=lambda: False):
    signatures = set()
    consumed = units = 0
    complete = True
    sides = [0, 0]
    for side, inputs in enumerate((discovery, target)):
        for item in inputs:
            if not item.stream.included or not item.stream.extent:
                continue
            if item.wire_identity is None or item.sequence_origin is None:
                complete = False
                continue
            if any(status != "known" for _, _, status in item.source.ranges):
                complete = False
            for left, right in item.source.known_runs(0):
                position = left + (-(item.sequence_origin + left) % BLOCK)
                blocks = ((p, BLOCK) for p in range(position, right - BLOCK + 1, BLOCK))
                if right - left < BLOCK * 2:
                    blocks = chain(((left, right - left),), blocks)
                for position, size in blocks:
                    if cancelled():
                        raise WorkCancelled
                    if (
                        consumed + size > budget.max_scanned_bytes
                        or units >= budget.max_sample_units
                    ):
                        return (
                            "unverified",
                            "Recording overlap scan stopped at the frozen byte/unit budget",
                        )
                    data = item.source.read(position, size)
                    consumed += size
                    units += 1
                    sides[side] += 1
                    signature = (
                        item.wire_identity,
                        (item.sequence_origin + position) % MOD,
                        size,
                        hashlib.sha256(data).hexdigest(),
                    )
                    if side == 0:
                        signatures.add(signature)
                    elif signature in signatures:
                        return (
                            "exploratory",
                            "Shared TCP sequence-aligned bytes across recordings; "
                            "capture segmentation or different capture hashes "
                            "do not make them independent",
                        )
    if not complete:
        return (
            "unverified",
            "Overlap could not be checked over unavailable/ambiguous TCP coordinates or bytes",
        )
    # Small exchanges can still be held out, but do not provide an overlap proof.
    return (
        "independent",
        f"{VERSION}: {sides[0]}/{sides[1]} known wire blocks compared; "
        "disjoint capture scope and declared recording groups remain assumptions; "
        "short or uncaptured overlaps are not established",
    )

"""Search contiguous, known byte ranges; never bridge missing/ambiguous bytes."""

from protocol_lab.capture.index import WorkCancelled


def search_known(
    chunks,
    pattern: bytes,
    start=0,
    max_matches=1000,
    cancelled=lambda: False,
    progress=lambda _position: None,
):
    if not 1 <= len(pattern) <= 256 or start < 0 or not 1 <= max_matches <= 1000:
        raise ValueError("Search needs 1..256 bytes, nonnegative start and at most 1000 matches")
    matches, skipped = [], []
    skipped_bytes = 0
    carry = b""
    previous_end = None
    for offset, end, data in chunks:
        if cancelled():
            raise WorkCancelled
        if end <= start:
            continue
        progress(end)
        if data is None:
            carry = b""
            previous_end = None
            skipped_bytes += end - max(offset, start)
            if len(skipped) < 100:
                skipped.append([max(offset, start), end])
            continue
        if offset != previous_end:
            carry = b""
        left = max(offset, start)
        data = data[left - offset :]
        combined = carry + data
        base = left - len(carry)
        position = max(0, start - base)
        while (position := combined.find(pattern, position)) != -1:
            match = base + position
            # Earlier carry alone was searched in the previous chunk.
            if match + len(pattern) > left:
                matches.append(match)
                if len(matches) == max_matches:
                    return dict(
                        matches=matches,
                        complete=False,
                        next_offset=match + 1,
                        skipped_ranges=skipped,
                        skipped_bytes=skipped_bytes,
                    )
            position += 1
            if cancelled():
                raise WorkCancelled
        carry = combined[-(len(pattern) - 1) :] if len(pattern) > 1 else b""
        previous_end = end
    return dict(
        matches=matches,
        complete=True,
        next_offset=None,
        skipped_ranges=skipped,
        skipped_bytes=skipped_bytes,
    )

"""Read only known reconstructed bytes through exact capture-file evidence."""

from bisect import bisect_right

from protocol_lab.framing.engine import StreamInput


def stream_input(stream, spans, source):
    spans = list(spans)
    ends = [s.byte_range.end for s in spans]

    def read(offset, length):
        output = bytearray()
        index = bisect_right(ends, offset)
        end = offset + length
        while offset < end:
            if index >= len(spans):
                raise ValueError("Requested stream range is unavailable")
            span = spans[index]
            if span.status != "known" or not span.sources or offset < span.byte_range.start:
                raise ValueError("Requested framing byte is not known")
            right = min(end, span.byte_range.end)
            source.seek(span.sources[0].file_offset + offset - span.byte_range.start)
            data = source.read(right - offset)
            if len(data) != right - offset:
                raise ValueError("Framing source range unavailable")
            output.extend(data)
            offset = right
            index += 1
        return bytes(output)

    return StreamInput(
        stream.extent, [(s.byte_range.start, s.byte_range.end, s.status) for s in spans], read
    )

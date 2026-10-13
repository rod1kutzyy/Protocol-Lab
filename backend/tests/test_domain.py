from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from protocol_lab.domain.models import ByteRange, Capture, Endpoint, SourceRange, StreamRange


def test_ranges_are_nonempty_and_source_lengths_match():
    for start, end in [(1, 1), (2, 1), (-1, 4)]:
        with pytest.raises(ValidationError):
            ByteRange(start=start, end=end)
    anchor = StreamRange(
        stream_id=uuid4(), reconstruction_version="v1", byte_range=ByteRange(start=0, end=3)
    )
    with pytest.raises(ValidationError):
        SourceRange(
            capture_id=uuid4(),
            packet_id=uuid4(),
            stream=anchor,
            packet_payload_range=ByteRange(start=0, end=2),
        )


@pytest.mark.parametrize(
    "path", ["/tmp/source.pcap", "../source.pcap", "a/../source.pcap", "C:\\source.pcap", ""]
)
def test_capture_rejects_nonportable_paths(path):
    with pytest.raises(ValidationError):
        Capture(
            id=uuid4(),
            project_id=uuid4(),
            sha256="a" * 64,
            format="pcap",
            relative_path=path,
            size_bytes=0,
            imported_at=datetime.now(UTC),
        )


def test_domain_records_are_frozen_and_ipv4_only():
    endpoint = Endpoint(address="127.0.0.1", port=8000)
    with pytest.raises(ValidationError):
        endpoint.port = 9000
    with pytest.raises(ValidationError):
        Endpoint(address="::1", port=8000)

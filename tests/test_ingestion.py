"""
Unit tests for ironclad.ingestion.pcap_reader.
"""

from pathlib import Path
import pytest

from ironclad.core.exceptions import PCAPIngestionError
from ironclad.ingestion.pcap_reader import PCAPReader


def test_pcap_reader_success(temp_pcap_path: Path):
    reader = PCAPReader(temp_pcap_path, batch_size=2)
    packets = list(reader.stream_packets())
    assert len(packets) == 5
    assert reader.count_packets() == 5


def test_pcap_reader_batching(temp_pcap_path: Path):
    reader = PCAPReader(temp_pcap_path, batch_size=2)
    batches = list(reader.stream_batches())
    assert len(batches) == 3
    assert len(batches[0]) == 2
    assert len(batches[1]) == 2
    assert len(batches[2]) == 1


def test_pcap_reader_max_packets(temp_pcap_path: Path):
    reader = PCAPReader(temp_pcap_path, max_packets=3)
    packets = list(reader.stream_packets())
    assert len(packets) == 3


def test_pcap_reader_nonexistent_file():
    with pytest.raises(PCAPIngestionError) as exc_info:
        PCAPReader("path/does/not/exist_12345.pcap")
    assert "does not exist" in str(exc_info.value)


def test_pcap_reader_empty_file(empty_pcap_path: Path):
    with pytest.raises(PCAPIngestionError) as exc_info:
        PCAPReader(empty_pcap_path)
    assert "empty" in str(exc_info.value)

"""
IRONCLAD PCAP Ingestion Engine.

Provides memory-efficient streaming, batch reading, and format validation for
PCAP and PCAPNG network trace captures. Integrates Scapy with optional PyShark fallback.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Generator, Iterator, List, Optional, Union

from scapy.all import Packet, PcapReader, rdpcap

from ironclad.core.exceptions import PCAPIngestionError
from ironclad.core.logging import get_logger

logger = get_logger("ingestion.pcap_reader")

# Standard PCAP/PCAPNG Magic Number Signatures
MAGIC_PCAP_MICRO = b"\xa1\xb2\xc3\xd4"
MAGIC_PCAP_NANO = b"\xa1\xb2\x3c\x4d"
MAGIC_PCAP_SWAPPED = b"\xd4\xc3\xb2\xa1"
MAGIC_PCAPNG = b"\x0a\x0d\x0d\x0a"


class PCAPReader:
    """
    Production-grade streaming reader for PCAP and PCAPNG files using Scapy.

    Streams packets iteratively without consuming unbounded memory on large captures.
    """

    def __init__(
        self,
        filepath: Union[str, Path],
        batch_size: int = 1000,
        max_packets: Optional[int] = None,
        bpf_filter: str = "",
    ) -> None:
        """
        Initialize the PCAP reader.

        Args:
            filepath: Path to the target PCAP/PCAPNG file.
            batch_size: Batch size for chunked streaming.
            max_packets: Optional maximum number of packets to process.
            bpf_filter: Berkeley Packet Filter string (optional).
        """
        self.filepath = Path(filepath).resolve()
        self.batch_size = max(1, batch_size)
        self.max_packets = max_packets
        self.bpf_filter = bpf_filter
        self._validate_file()

    def _validate_file(self) -> None:
        """Verify file existence, readability, non-zero size, and magic signature."""
        if not self.filepath.exists():
            raise PCAPIngestionError(
                f"Capture file does not exist: {self.filepath}"
            )
        if not self.filepath.is_file():
            raise PCAPIngestionError(
                f"Path is not a regular file: {self.filepath}"
            )
        if self.filepath.stat().st_size == 0:
            raise PCAPIngestionError(
                f"Capture file is empty (0 bytes): {self.filepath}"
            )

        # Inspect magic bytes
        try:
            with open(self.filepath, "rb") as f:
                header = f.read(4)
                if header not in (
                    MAGIC_PCAP_MICRO,
                    MAGIC_PCAP_NANO,
                    MAGIC_PCAP_SWAPPED,
                    MAGIC_PCAPNG,
                ):
                    logger.warning(
                        "File header does not match standard PCAP/PCAPNG magic numbers. "
                        "Attempting to read anyway: %s",
                        self.filepath,
                    )
        except OSError as e:
            raise PCAPIngestionError(
                f"Failed to read file header: {self.filepath}", details={"error": str(e)}
            ) from e

    def stream_packets(self) -> Generator[Packet, None, None]:
        """
        Generator streaming packets one by one to maintain minimal memory footprint.

        Yields:
            Scapy Packet instances.
        """
        logger.info(
            "Starting streaming ingestion for: %s (max_packets=%s)",
            self.filepath.name,
            self.max_packets,
        )
        count = 0
        reader = None
        try:
            reader = PcapReader(str(self.filepath))
            for pkt in reader:
                yield pkt
                count += 1
                if self.max_packets is not None and count >= self.max_packets:
                    logger.info("Reached maximum packet limit (%d). Halting stream.", count)
                    break
        except Exception as e:
            logger.error("Error reading packet stream from %s at packet #%d: %s", self.filepath, count, e)
            raise PCAPIngestionError(
                f"Failed streaming packets from {self.filepath.name}",
                details={"packet_count": count, "error": str(e)},
            ) from e
        finally:
            if reader is not None:
                reader.close()
            logger.info("Completed packet ingestion. Total packets yielded: %d", count)

    def stream_batches(self) -> Generator[List[Packet], None, None]:
        """
        Yield packets in fixed-size batches for vectorized or bulk processing.

        Yields:
            Lists of Scapy Packet instances up to batch_size.
        """
        batch: List[Packet] = []
        for pkt in self.stream_packets():
            batch.append(pkt)
            if len(batch) >= self.batch_size:
                yield batch
                batch = []
        if batch:
            yield batch

    def read_all(self) -> List[Packet]:
        """
        Read all packets into memory. Useful for smaller test traces.

        Returns:
            List of Scapy Packet instances.
        """
        return list(self.stream_packets())

    def count_packets(self) -> int:
        """
        Count total packets in the capture without keeping them in memory.

        Returns:
            Total packet count.
        """
        count = 0
        for _ in self.stream_packets():
            count += 1
        return count


class PySharkReader:
    """
    Optional packet reader leveraging PyShark (TShark wrapper).
    Used when deep application-layer dissections (Wireshark dissectors) are required.
    """

    def __init__(
        self,
        filepath: Union[str, Path],
        tshark_path: Optional[str] = None,
        display_filter: Optional[str] = None,
    ) -> None:
        """
        Initialize the PyShark reader.

        Args:
            filepath: Target PCAP path.
            tshark_path: Optional explicit path to tshark executable (crucial for Windows).
            display_filter: Wireshark display filter string.
        """
        self.filepath = Path(filepath).resolve()
        self.tshark_path = tshark_path or os.environ.get("TSHARK_PATH")
        self.display_filter = display_filter
        self._check_availability()

    def _check_availability(self) -> None:
        """Verify PyShark library is installed and available."""
        try:
            import pyshark  # noqa: F401
        except ImportError as e:
            raise PCAPIngestionError(
                "PyShark is not installed. To use PySharkReader, install pyshark via pip "
                "(pip install pyshark) and ensure Wireshark/TShark is in PATH."
            ) from e

    def stream_packets(self) -> Generator[Any, None, None]:
        """
        Stream parsed packets via PyShark FileCapture.

        Yields:
            pyshark.packet.packet.Packet objects.
        """
        import pyshark

        logger.info("Opening PyShark capture on: %s", self.filepath.name)
        capture = pyshark.FileCapture(
            str(self.filepath),
            tshark_path=self.tshark_path,
            display_filter=self.display_filter,
            keep_packets=False,  # Essential to prevent memory leaks in PyShark
        )
        try:
            for packet in capture:
                yield packet
        except Exception as e:
            raise PCAPIngestionError(
                f"PyShark ingestion failure on {self.filepath.name}",
                details={"error": str(e)},
            ) from e
        finally:
            capture.close()

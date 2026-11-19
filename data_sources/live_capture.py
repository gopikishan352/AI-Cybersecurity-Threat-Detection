"""
Live Packet Capture Adapter (Optional Architecture).
Provides the interface and implementation blueprint for future live network packet capture using Scapy.
Designed so Scapy and administrative privileges are NOT required for normal operation.
"""

from .base_source import BaseTrafficSource


class LivePacketCaptureSource(BaseTrafficSource):
    """
    Adapter for live network interface sniffing.
    Falls back gracefully if Scapy is missing or elevated privileges are absent.
    """

    def __init__(self, interface=None):
        self.interface = interface
        self._scapy_available = False
        self._check_scapy()

    def _check_scapy(self):
        try:
            import scapy.all  # noqa: F401
            self._scapy_available = True
        except ImportError:
            self._scapy_available = False

    def is_available(self):
        # Only available if Scapy is installed and adapter initialized
        return self._scapy_available

    def get_source_type(self):
        return "Live Network Packet Sniffer (Scapy)"

    def get_sample(self):
        """
        Extract NSL-KDD compatible flow features from live packet stream.
        If unavailable, returns None with guidance.
        """
        if not self.is_available():
            raise RuntimeError(
                "Live packet capture requires 'scapy' and administrator/root privileges. "
                "Defaulting to Simulated NSL-KDD Replay."
            )
        # Placeholder for live flow reconstruction engine
        return None

    def get_batch(self, count=5):
        if not self.is_available():
            return []
        return [self.get_sample() for _ in range(count)]

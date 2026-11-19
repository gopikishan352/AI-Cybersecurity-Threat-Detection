"""
Abstract Base Class for Network Traffic Sources.
Allows switching between simulated dataset replays and live network interfaces.
"""
from abc import ABC, abstractmethod


class BaseTrafficSource(ABC):
    """Abstract interface for all network traffic sources."""

    @abstractmethod
    def get_sample(self):
        """Retrieve a single traffic sample record with feature values and synthesized IP metadata."""
        pass

    @abstractmethod
    def get_batch(self, count=5):
        """Retrieve a batch of traffic sample records."""
        pass

    @abstractmethod
    def is_available(self):
        """Check if this traffic source is ready and available."""
        pass

    @abstractmethod
    def get_source_type(self):
        """Return human-readable source label (e.g. 'Simulated NSL-KDD Replay')."""
        pass

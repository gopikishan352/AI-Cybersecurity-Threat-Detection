"""
Dataset Replay Traffic Source.
Reads records from the NSL-KDD benchmark dataset to simulate incoming network traffic events.
Clearly labeled as simulated / replay traffic.
"""

import os
import random
from datetime import datetime
import pandas as pd
from utils.constants import COLUMNS, FEATURE_COLUMNS
from .base_source import BaseTrafficSource


class DatasetReplaySource(BaseTrafficSource):
    """Replays records from NSL-KDD test dataset with realistic network metadata."""

    def __init__(self, dataset_path=None):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if dataset_path is None:
            dataset_path = os.path.join(base_dir, "dataset", "KDDTest+.txt")
            if not os.path.exists(dataset_path):
                dataset_path = os.path.join(base_dir, "dataset", "KDDTrain+.txt")

        self.dataset_path = dataset_path
        self.df = None
        self.current_index = 0
        self._load_dataset()

    def _load_dataset(self):
        if os.path.exists(self.dataset_path):
            try:
                self.df = pd.read_csv(self.dataset_path, names=COLUMNS)
            except Exception as e:
                print(f"[DatasetReplaySource] Error loading dataset: {e}")
                self.df = None

    def is_available(self):
        return self.df is not None and len(self.df) > 0

    def get_source_type(self):
        return "Simulated NSL-KDD Replay"

    def _generate_synthetic_network_meta(self, row):
        """Generate realistic SOC metadata (IPs, Ports, Timestamps) for replay events."""
        protocol = str(row.get("protocol_type", "tcp")).lower()
        service = str(row.get("service", "http")).lower()

        # Map common services to ports
        service_ports = {
            "http": 80, "http_443": 443, "ssl": 443, "smtp": 25, "ftp": 21,
            "ftp_data": 20, "telnet": 23, "ssh": 22, "domain_u": 53, "dns": 53,
            "finger": 79, "echo": 7, "private": random.randint(1024, 65535)
        }
        dst_port = service_ports.get(service, random.randint(1024, 65535))
        src_port = random.randint(10240, 65535)

        # Generate realistic internal vs external IP pairs
        external_subnets = ["198.51.100", "203.0.113", "185.220.101", "45.33.32", "194.26.29"]
        internal_subnets = ["192.168.1", "10.0.0", "172.16.10"]

        src_ip = f"{random.choice(external_subnets)}.{random.randint(2, 254)}"
        dst_ip = f"{random.choice(internal_subnets)}.{random.randint(10, 50)}"

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        return {
            "timestamp": timestamp,
            "source": f"{src_ip}:{src_port}",
            "destination": f"{dst_ip}:{dst_port}",
            "protocol": protocol.upper(),
            "service": service
        }

    def get_sample(self):
        """Retrieve a single sequential or sampled record."""
        if not self.is_available():
            return None

        # Sample or iterate
        idx = self.current_index % len(self.df)
        self.current_index += 1
        row = self.df.iloc[idx]

        meta = self._generate_synthetic_network_meta(row)
        features = row[FEATURE_COLUMNS].tolist()
        ground_truth = str(row.get("label", "normal")).strip(".")

        return {
            **meta,
            "features": features,
            "ground_truth": ground_truth,
            "source_type": self.get_source_type()
        }

    def get_batch(self, count=5):
        """Retrieve a batch of simulated records."""
        return [self.get_sample() for _ in range(count) if self.is_available()]

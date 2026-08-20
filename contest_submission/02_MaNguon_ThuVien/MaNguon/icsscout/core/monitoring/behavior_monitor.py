"""Behavior Monitoring and Anomaly Detection for OT Devices"""

from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from collections import deque
import threading
import time
import statistics

from icsscout.core.protocols.base import BaseProtocolClient
from icsscout.utils.logger import get_logger


@dataclass
class Sample:
    """Device state sample"""
    timestamp: datetime
    cpu_load: Optional[float] = None
    memory_usage: Optional[float] = None
    network_traffic: int = 0
    active_connections: int = 0
    memory_reads: int = 0
    memory_writes: int = 0
    custom_metrics: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Baseline:
    """Normal behavior baseline"""
    cpu_load_mean: float = 0.0
    cpu_load_std: float = 0.0
    memory_usage_mean: float = 0.0
    memory_usage_std: float = 0.0
    memory_reads_mean: float = 0.0
    memory_reads_std: float = 0.0
    memory_writes_mean: float = 0.0
    memory_writes_std: float = 0.0
    typical_connections: List[str] = field(default_factory=list)
    sample_count: int = 0

    @classmethod
    def from_samples(cls, samples: List[Sample]) -> 'Baseline':
        """Create baseline from samples"""
        if not samples:
            return cls()

        cpu_loads = [s.cpu_load for s in samples if s.cpu_load is not None]
        memory_usage = [s.memory_usage for s in samples if s.memory_usage is not None]
        reads = [s.memory_reads for s in samples]
        writes = [s.memory_writes for s in samples]

        return cls(
            cpu_load_mean=statistics.mean(cpu_loads) if cpu_loads else 0,
            cpu_load_std=statistics.stdev(cpu_loads) if len(cpu_loads) > 1 else 0,
            memory_usage_mean=statistics.mean(memory_usage) if memory_usage else 0,
            memory_usage_std=statistics.stdev(memory_usage) if len(memory_usage) > 1 else 0,
            memory_reads_mean=statistics.mean(reads) if reads else 0,
            memory_reads_std=statistics.stdev(reads) if len(reads) > 1 else 0,
            memory_writes_mean=statistics.mean(writes) if writes else 0,
            memory_writes_std=statistics.stdev(writes) if len(writes) > 1 else 0,
            sample_count=len(samples)
        )


@dataclass
class Anomaly:
    """Detected anomaly"""
    type: str
    severity: str  # HIGH, MEDIUM, LOW
    description: str
    timestamp: datetime
    details: Dict[str, Any] = field(default_factory=dict)


class BehaviorMonitor:
    """
    Monitor PLC behavior and detect anomalies

    Features:
    - Baseline establishment
    - Statistical anomaly detection
    - Continuous monitoring
    - Historical tracking
    """

    def __init__(self, client: BaseProtocolClient, history_size: int = 1000):
        """
        Initialize behavior monitor

        Args:
            client: Protocol client for device
            history_size: Number of samples to keep in history
        """
        self.client = client
        self.logger = get_logger('BehaviorMonitor')

        self.baseline: Optional[Baseline] = None
        self.history: deque = deque(maxlen=history_size)
        self.anomalies: List[Anomaly] = []

        # Monitoring control
        self.is_monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()

        # Callbacks
        self.anomaly_callbacks: List[Callable] = []

    def establish_baseline(self, duration: int = 3600, interval: float = 1.0) -> Baseline:
        """
        Establish normal behavior baseline

        Args:
            duration: Monitoring duration in seconds
            interval: Sample interval in seconds

        Returns:
            Baseline object
        """
        self.logger.info(f"Establishing baseline for {duration}s...")

        samples = []
        start_time = time.time()

        while time.time() - start_time < duration:
            try:
                sample = self._collect_sample()
                samples.append(sample)
                time.sleep(interval)
            except Exception as e:
                self.logger.warning(f"Sample collection failed: {e}")

        self.baseline = Baseline.from_samples(samples)
        self.logger.info(f"Baseline established from {len(samples)} samples")

        return self.baseline

    def start_monitoring(self, interval: float = 1.0) -> None:
        """
        Start continuous monitoring

        Args:
            interval: Sample interval in seconds
        """
        if self.is_monitoring:
            self.logger.warning("Monitoring already active")
            return

        if not self.baseline:
            self.logger.warning("No baseline established. Please run establish_baseline() first.")
            return

        self.logger.info("Starting continuous monitoring...")
        self.is_monitoring = True
        self.stop_event.clear()

        def monitor_loop():
            while not self.stop_event.is_set():
                try:
                    sample = self._collect_sample()
                    self.history.append(sample)

                    # Check for anomalies
                    anomaly = self._detect_anomaly(sample, self.baseline)
                    if anomaly:
                        self.anomalies.append(anomaly)
                        for callback in self.anomaly_callbacks:
                            try:
                                callback(anomaly)
                            except Exception as e:
                                self.logger.error(f"Anomaly callback error: {e}")

                    time.sleep(interval)
                except Exception as e:
                    self.logger.error(f"Monitoring error: {e}")

        self.monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self) -> None:
        """Stop continuous monitoring"""
        self.logger.info("Stopping monitoring...")
        self.stop_event.set()

        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)

        self.is_monitoring = False

    def _collect_sample(self) -> Sample:
        """Collect current state sample"""
        # This is simplified - would query actual device metrics
        sample = Sample(
            timestamp=datetime.now(),
            cpu_load=None,  # Would query from device
            memory_usage=None,
            network_traffic=0,
            active_connections=0,
            memory_reads=0,
            memory_writes=0
        )

        return sample

    def _detect_anomaly(self, sample: Sample, baseline: Baseline) -> Optional[Anomaly]:
        """Detect anomalies in sample"""
        # Statistical anomaly detection (3-sigma rule)
        threshold = 3.0

        # CPU load anomaly
        if sample.cpu_load and baseline.cpu_load_std > 0:
            z_score = abs(sample.cpu_load - baseline.cpu_load_mean) / baseline.cpu_load_std
            if z_score > threshold:
                return Anomaly(
                    type="CPU_SPIKE",
                    severity="MEDIUM",
                    description=f"CPU load {sample.cpu_load:.1f}% deviates from baseline",
                    timestamp=sample.timestamp,
                    details={
                        'value': sample.cpu_load,
                        'baseline_mean': baseline.cpu_load_mean,
                        'z_score': z_score
                    }
                )

        # Memory writes anomaly
        if baseline.memory_writes_std > 0:
            z_score = abs(sample.memory_writes - baseline.memory_writes_mean) / baseline.memory_writes_std
            if z_score > threshold:
                return Anomaly(
                    type="EXCESSIVE_WRITES",
                    severity="HIGH",
                    description=f"Unusual number of memory writes: {sample.memory_writes}",
                    timestamp=sample.timestamp,
                    details={
                        'value': sample.memory_writes,
                        'baseline_mean': baseline.memory_writes_mean
                    }
                )

        return None

    def add_anomaly_callback(self, callback: Callable[[Anomaly], None]) -> None:
        """Add callback for anomaly detection"""
        self.anomaly_callbacks.append(callback)

    def get_anomalies(self, since: Optional[datetime] = None) -> List[Anomaly]:
        """Get detected anomalies"""
        if since:
            return [a for a in self.anomalies if a.timestamp >= since]
        return self.anomalies.copy()

    def get_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics"""
        return {
            'baseline_established': self.baseline is not None,
            'samples_collected': len(self.history),
            'anomalies_detected': len(self.anomalies),
            'is_monitoring': self.is_monitoring
        }

"""
ThreatHunter - ML Models for Threat Detection
"""

import numpy as np
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
import pickle
import hashlib


@dataclass
class Prediction:
    """ML prediction result."""
    threat_type: str
    confidence: float
    features: Dict[str, float]
    model_version: str


class ThreatDetectionModel:
    """ML model for threat detection."""
    
    def __init__(self, model_path: str = None):
        self.model_version = "3.0.0"
        self.feature_names = [
            "packet_rate", "byte_rate", "connection_count",
            "unique_ports", "dns_queries", "failed_logins",
            "process_count", "file_changes", "registry_changes"
        ]
        self.thresholds = {
            "ddos": 0.85,
            "port_scan": 0.80,
            "malware": 0.90,
            "exfiltration": 0.88,
            "lateral_movement": 0.82
        }
    
    def extract_features(self, events: List[Dict]) -> np.ndarray:
        """Extract features from events."""
        features = np.zeros(len(self.feature_names))
        
        for event in events:
            if event.get("type") == "network":
                features[0] += event.get("packet_rate", 0)
                features[1] += event.get("byte_rate", 0)
                features[2] += event.get("connections", 0)
                features[3] += event.get("unique_ports", 0)
            elif event.get("type") == "dns":
                features[4] += event.get("queries", 0)
            elif event.get("type") == "auth":
                features[5] += event.get("failed_logins", 0)
            elif event.get("type") == "endpoint":
                features[6] += event.get("process_count", 0)
                features[7] += event.get("file_changes", 0)
                features[8] += event.get("registry_changes", 0)
        
        return features
    
    def predict(self, features: np.ndarray) -> List[Prediction]:
        """Make predictions based on features."""
        predictions = []
        
        # DDoS detection
        ddos_score = self._detect_ddos(features)
        if ddos_score > self.thresholds["ddos"]:
            predictions.append(Prediction(
                threat_type="DDoS",
                confidence=ddos_score,
                features={"packet_rate": features[0], "byte_rate": features[1]},
                model_version=self.model_version
            ))
        
        # Port scan detection
        scan_score = self._detect_port_scan(features)
        if scan_score > self.thresholds["port_scan"]:
            predictions.append(Prediction(
                threat_type="Port Scan",
                confidence=scan_score,
                features={"unique_ports": features[3], "connection_count": features[2]},
                model_version=self.model_version
            ))
        
        # Malware detection
        malware_score = self._detect_malware(features)
        if malware_score > self.thresholds["malware"]:
            predictions.append(Prediction(
                threat_type="Malware",
                confidence=malware_score,
                features={"process_count": features[6], "file_changes": features[7]},
                model_version=self.model_version
            ))
        
        return predictions
    
    def _detect_ddos(self, features: np.ndarray) -> float:
        """Detect DDoS patterns."""
        packet_rate = features[0]
        byte_rate = features[1]
        
        if packet_rate > 1000000:  # 1M packets/sec
            return min(0.95, 0.8 + (packet_rate / 10000000))
        return 0.0
    
    def _detect_port_scan(self, features: np.ndarray) -> float:
        """Detect port scanning."""
        unique_ports = features[3]
        
        if unique_ports > 100:
            return min(0.98, 0.7 + (unique_ports / 1000))
        return 0.0
    
    def _detect_malware(self, features: np.ndarray) -> float:
        """Detect malware behavior."""
        process_count = features[6]
        file_changes = features[7]
        
        if file_changes > 50:
            return min(0.99, 0.85 + (file_changes / 500))
        return 0.0


class AnomalyDetector:
    """Anomaly detection using statistical methods."""
    
    def __init__(self, sensitivity: float = 0.95):
        self.sensitivity = sensitivity
        self.baseline = {}
        self.std_devs = {}
    
    def update_baseline(self, metrics: Dict[str, float]):
        """Update baseline metrics."""
        for key, value in metrics.items():
            if key not in self.baseline:
                self.baseline[key] = []
            self.baseline[key].append(value)
            
            # Keep last 1000 values
            if len(self.baseline[key]) > 1000:
                self.baseline[key] = self.baseline[key][-1000:]
            
            # Update standard deviation
            self.std_devs[key] = np.std(self.baseline[key])
    
    def detect_anomaly(self, metrics: Dict[str, float]) -> List[Tuple[str, float]]:
        """Detect anomalies in metrics."""
        anomalies = []
        
        for key, value in metrics.items():
            if key in self.baseline and len(self.baseline[key]) > 10:
                mean = np.mean(self.baseline[key])
                std = self.std_devs.get(key, 1)
                
                if std > 0:
                    z_score = abs(value - mean) / std
                    if z_score > (3 * self.sensitivity):
                        anomalies.append((key, z_score))
        
        return anomalies


class IOCMatcher:
    """Match indicators of compromise."""
    
    def __init__(self):
        self.iocs = {
            "ip": set(),
            "domain": set(),
            "hash": set(),
            "url": set()
        }
    
    def load_iocs(self, ioc_type: str, values: List[str]):
        """Load IOCs into matcher."""
        self.iocs[ioc_type].update(values)
    
    def match(self, indicator: str, ioc_type: str) -> bool:
        """Check if indicator matches known IOC."""
        return indicator in self.iocs.get(ioc_type, set())
    
    def match_all(self, indicators: Dict[str, str]) -> List[Dict[str, str]]:
        """Match multiple indicators."""
        matches = []
        for value, ioc_type in indicators.items():
            if self.match(value, ioc_type):
                matches.append({"value": value, "type": ioc_type})
        return matches


# Export
__all__ = [
    "ThreatDetectionModel",
    "AnomalyDetector",
    "IOCMatcher",
    "Prediction"
]

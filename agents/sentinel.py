"""
ThreatHunter - Sentinel Agent
Endpoint protection and behavior analysis.
"""

import asyncio
import hashlib
from datetime import datetime
from typing import List, Dict, Any, Set
from core import BaseAgent, Threat, ThreatLevel, DetectionEngine


class SentinelAgent(BaseAgent):
    """
    Sentinel Agent - Endpoint Protection
    
    Responsibilities:
    - Monitor process execution
    - File integrity monitoring
    - Registry change detection
    - Behavioral analysis
    - Memory protection
    """
    
    def __init__(self, engine: DetectionEngine, config: Dict[str, Any] = None):
        super().__init__("Sentinel", engine)
        self.config = config or {}
        self.monitored_paths = config.get("monitored_paths", [])
        self.known_good_hashes: Set[str] = set()
        self.suspicious_processes = set()
        
        # Behavior rules
        self.malware_behaviors = [
            "persistence_mechanism",
            "privilege_escalation",
            "credential_dumping",
            "lateral_movement",
            "defense_evasion"
        ]
    
    async def process(self):
        """Main processing loop for endpoint monitoring."""
        try:
            # Monitor processes
            processes = await self._get_running_processes()
            for proc in processes:
                await self._analyze_process(proc)
            
            # Monitor file changes
            await self._check_file_integrity()
            
            # Monitor registry
            await self._check_registry_changes()
            
            # Memory analysis
            await self._analyze_memory()
            
            self.metrics.events_processed += len(processes)
            
        except Exception as e:
            self.metrics.errors += 1
    
    async def _get_running_processes(self) -> List[Dict[str, Any]]:
        """Get list of running processes."""
        return [
            {"pid": 1234, "name": "svchost.exe", "path": "C:\\Windows\\System32", "user": "SYSTEM"},
            {"pid": 5678, "name": "chrome.exe", "path": "C:\\Program Files", "user": "user"},
            {"pid": 9012, "name": "powershell.exe", "path": "C:\\Windows\\System32", "user": "admin"},
        ]
    
    async def _analyze_process(self, process: Dict[str, Any]):
        """Analyze process behavior."""
        name = process["name"]
        path = process["path"]
        
        # Check for suspicious process names
        suspicious_names = ["mimikatz", "psexec", "wce", "gsecdump"]
        if any(s in name.lower() for s in suspicious_names):
            threat = Threat(
                id=f"SENT-PROC-{datetime.utcnow().timestamp()}",
                name="Malicious Process Detected",
                level=ThreatLevel.CRITICAL,
                source="Sentinel Agent",
                timestamp=datetime.utcnow(),
                details={
                    "process": name,
                    "pid": process["pid"],
                    "path": path,
                    "user": process["user"]
                },
                iocs=[name, path],
                mitre_techniques=["T1003", "T1055"],
                confidence=0.99
            )
            self.report_threat(threat)
        
        # Check for LOLBins (Living Off the Land)
        lolbins = ["powershell", "cmd", "wscript", "cscript", "mshta", "regsvr32"]
        if any(lol in name.lower() for lol in lolbins):
            # Check command line arguments
            cmdline = process.get("cmdline", "")
            suspicious_args = ["-enc", "bypass", "hidden", "downloadstring", "invoke-expression"]
            if any(arg in cmdline.lower() for arg in suspicious_args):
                threat = Threat(
                    id=f"SENT-LOLBIN-{datetime.utcnow().timestamp()}",
                    name="Suspicious LOLBin Usage",
                    level=ThreatLevel.HIGH,
                    source="Sentinel Agent",
                    timestamp=datetime.utcnow(),
                    details={
                        "process": name,
                        "pid": process["pid"],
                        "command_line": cmdline,
                        "detection": "Suspicious arguments in LOLBin"
                    },
                    iocs=[cmdline],
                    mitre_techniques=["T1059.001", "T1218"],
                    confidence=0.92
                )
                self.report_threat(threat)
    
    async def _check_file_integrity(self):
        """Monitor file system changes."""
        critical_files = [
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "/etc/passwd",
            "/etc/shadow"
        ]
        
        for filepath in critical_files:
            current_hash = await self._calculate_hash(filepath)
            if filepath in self.known_good_hashes and current_hash not in self.known_good_hashes:
                threat = Threat(
                    id=f"SENT-FIM-{datetime.utcnow().timestamp()}",
                    name="File Integrity Violation",
                    level=ThreatLevel.HIGH,
                    source="Sentinel Agent",
                    timestamp=datetime.utcnow(),
                    details={
                        "file": filepath,
                        "detection": "Critical file modified",
                        "new_hash": current_hash
                    },
                    iocs=[filepath, current_hash],
                    mitre_techniques=["T1565.001"],
                    confidence=0.95
                )
                self.report_threat(threat)
    
    async def _calculate_hash(self, filepath: str) -> str:
        """Calculate file hash."""
        # Simulated hash calculation
        return hashlib.sha256(filepath.encode()).hexdigest()
    
    async def _check_registry_changes(self):
        """Monitor Windows registry changes."""
        run_keys = [
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
        ]
        
        # Simulated registry monitoring
        pass
    
    async def _analyze_memory(self):
        """Analyze process memory for malicious patterns."""
        # Memory scanning for injected code
        pass


# Export
__all__ = ["SentinelAgent"]

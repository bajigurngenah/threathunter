"""
ThreatHunter - AI-Powered Threat Detection Platform
Main engine coordinating 6 specialized agents.
"""

__version__ = "1.0.0"
__author__ = "ThreatHunter Team"

import asyncio
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("threathunter")


class ThreatLevel(Enum):
    """Threat severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AgentStatus(Enum):
    """Agent operational status."""
    ACTIVE = "active"
    IDLE = "idle"
    ERROR = "error"
    STOPPED = "stopped"


@dataclass
class Threat:
    """Represents a detected threat."""
    id: str
    name: str
    level: ThreatLevel
    source: str
    timestamp: datetime
    details: Dict[str, Any]
    iocs: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    confidence: float = 0.0
    false_positive: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "level": self.level.value,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
            "iocs": self.iocs,
            "mitre_techniques": self.mitre_techniques,
            "confidence": self.confidence,
            "false_positive": self.false_positive
        }


@dataclass
class AgentMetrics:
    """Agent performance metrics."""
    threats_detected: int = 0
    events_processed: int = 0
    false_positives: int = 0
    uptime_seconds: float = 0
    avg_response_time_ms: float = 0
    memory_usage_mb: float = 0
    cpu_usage_percent: float = 0


class DetectionEngine:
    """Core detection engine coordinating all agents."""
    
    def __init__(self):
        self.agents: Dict[str, 'BaseAgent'] = {}
        self.threats: List[Threat] = []
        self.metrics = AgentMetrics()
        self.running = False
        self._start_time = None
    
    def register_agent(self, name: str, agent: 'BaseAgent'):
        """Register a new agent with the engine."""
        self.agents[name] = agent
        logger.info(f"Agent registered: {name}")
    
    async def start(self, agents: Optional[List[str]] = None):
        """Start specified or all agents."""
        self.running = True
        self._start_time = datetime.utcnow()
        
        targets = agents or list(self.agents.keys())
        tasks = []
        
        for name in targets:
            if name in self.agents:
                tasks.append(self._run_agent(name))
        
        logger.info(f"Starting {len(tasks)} agents...")
        await asyncio.gather(*tasks)
    
    async def _run_agent(self, name: str):
        """Run a single agent."""
        agent = self.agents[name]
        try:
            agent.status = AgentStatus.ACTIVE
            logger.info(f"Agent {name} started")
            await agent.run()
        except Exception as e:
            agent.status = AgentStatus.ERROR
            logger.error(f"Agent {name} error: {e}")
    
    async def stop(self):
        """Stop all agents."""
        self.running = False
        for name, agent in self.agents.items():
            agent.status = AgentStatus.STOPPED
        logger.info("All agents stopped")
    
    def add_threat(self, threat: Threat):
        """Add a detected threat."""
        self.threats.append(threat)
        self.metrics.threats_detected += 1
        logger.warning(f"Threat detected: {threat.name} [{threat.level.value}]")
    
    def get_threats(self, level: Optional[ThreatLevel] = None) -> List[Threat]:
        """Get threats, optionally filtered by level."""
        if level:
            return [t for t in self.threats if t.level == level]
        return self.threats
    
    def get_status(self) -> Dict[str, Any]:
        """Get overall system status."""
        agent_statuses = {}
        for name, agent in self.agents.items():
            agent_statuses[name] = {
                "status": agent.status.value,
                "metrics": agent.metrics.__dict__
            }
        
        return {
            "running": self.running,
            "uptime": (datetime.utcnow() - self._start_time).total_seconds() if self._start_time else 0,
            "total_threats": len(self.threats),
            "threats_by_level": {
                level.value: len([t for t in self.threats if t.level == level])
                for level in ThreatLevel
            },
            "agents": agent_statuses
        }


class BaseAgent:
    """Base class for all ThreatHunter agents."""
    
    def __init__(self, name: str, engine: DetectionEngine):
        self.name = name
        self.engine = engine
        self.status = AgentStatus.IDLE
        self.metrics = AgentMetrics()
        self._start_time = None
    
    async def run(self):
        """Main agent loop. Override in subclass."""
        self._start_time = datetime.utcnow()
        while self.engine.running:
            await self.process()
            await asyncio.sleep(1)
    
    async def process(self):
        """Process events. Override in subclass."""
        raise NotImplementedError
    
    def report_threat(self, threat: Threat):
        """Report a detected threat to the engine."""
        self.engine.add_threat(threat)
        self.metrics.threats_detected += 1


# Export main components
__all__ = [
    "DetectionEngine",
    "BaseAgent",
    "Threat",
    "ThreatLevel",
    "AgentStatus",
    "AgentMetrics"
]

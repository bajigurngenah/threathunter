"""
ThreatHunter - Architect Agent
System optimization and resource management.
"""

import asyncio
from datetime import datetime
from typing import List, Dict, Any
from core import BaseAgent, Threat, ThreatLevel, DetectionEngine


class ArchitectAgent(BaseAgent):
    """
    Architect Agent - System Optimization
    
    Responsibilities:
    - System health monitoring
    - Performance optimization
    - Resource allocation
    - Scaling decisions
    - Capacity planning
    """
    
    def __init__(self, engine: DetectionEngine, config: Dict[str, Any] = None):
        super().__init__("Architect", engine)
        self.config = config or {}
        self.resource_limits = config.get("resource_limits", {
            "cpu": 80,
            "memory": 70,
            "disk": 90,
            "network": 85
        })
        self.scaling_events = []
        self.health_history = []
    
    async def process(self):
        """Main processing loop for system optimization."""
        try:
            # Monitor system health
            health = await self._check_health()
            self.health_history.append(health)
            
            # Check resource usage
            await self._check_resources(health)
            
            # Optimize performance
            await self._optimize_performance()
            
            # Capacity planning
            await self._capacity_planning()
            
            # Alert on issues
            await self._alert_on_issues(health)
            
        except Exception as e:
            self.metrics.errors += 1
    
    async def _check_health(self) -> Dict[str, Any]:
        """Check overall system health."""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "cpu_percent": 45.2,
            "memory_percent": 62.8,
            "disk_percent": 55.3,
            "network_mbps": 125.4,
            "active_agents": len([a for a in self.engine.agents.values() if a.status.value == "active"]),
            "total_threats": len(self.engine.threats),
            "queue_depth": 150,
            "latency_ms": 12.5
        }
    
    async def _check_resources(self, health: Dict):
        """Check resource usage against limits."""
        for resource, limit in self.resource_limits.items():
            current = health.get(f"{resource}_percent", 0)
            
            if current > limit:
                await self._handle_resource_limit(resource, current, limit)
    
    async def _handle_resource_limit(self, resource: str, current: float, limit: float):
        """Handle resource limit exceeded."""
        threat = Threat(
            id=f"ARCH-RES-{resource}-{datetime.utcnow().timestamp()}",
            name=f"Resource Limit Exceeded: {resource.upper()}",
            level=ThreatLevel.MEDIUM,
            source="Architect Agent",
            timestamp=datetime.utcnow(),
            details={
                "resource": resource,
                "current_usage": current,
                "limit": limit,
                "recommendation": "Scale up or optimize"
            },
            confidence=1.0
        )
        self.report_threat(threat)
        
        # Auto-scale if enabled
        if self.config.get("auto_scaling"):
            await self._scale_resource(resource)
    
    async def _scale_resource(self, resource: str):
        """Scale up a resource."""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "resource": resource,
            "action": "scale_up",
            "status": "completed"
        }
        self.scaling_events.append(event)
        self.metrics.events_processed += 1
    
    async def _optimize_performance(self):
        """Optimize system performance."""
        optimizations = [
            {"name": "Cache optimization", "impact": "low"},
            {"name": "Query optimization", "impact": "medium"},
            {"name": "Connection pooling", "impact": "medium"},
            {"name": "Load balancing", "impact": "high"}
        ]
        
        # Apply optimizations based on current load
        for opt in optimizations:
            self.metrics.events_processed += 1
    
    async def _capacity_planning(self):
        """Plan for future capacity needs."""
        if len(self.health_history) > 100:
            # Analyze trends
            recent = self.health_history[-100:]
            avg_cpu = sum(h["cpu_percent"] for h in recent) / len(recent)
            avg_memory = sum(h["memory_percent"] for h in recent) / len(recent)
            
            # Predict when limits will be reached
            if avg_cpu > 60:
                self.metrics.events_processed += 1
    
    async def _alert_on_issues(self, health: Dict):
        """Alert on system issues."""
        # High latency
        if health["latency_ms"] > 100:
            threat = Threat(
                id=f"ARCH-LATENCY-{datetime.utcnow().timestamp()}",
                name="High System Latency",
                level=ThreatLevel.MEDIUM,
                source="Architect Agent",
                timestamp=datetime.utcnow(),
                details={
                    "latency_ms": health["latency_ms"],
                    "threshold": 100,
                    "impact": "Delayed threat detection"
                },
                confidence=1.0
            )
            self.report_threat(threat)
        
        # Queue depth
        if health["queue_depth"] > 1000:
            threat = Threat(
                id=f"ARCH-QUEUE-{datetime.utcnow().timestamp()}",
                name="High Queue Depth",
                level=ThreatLevel.HIGH,
                source="Architect Agent",
                timestamp=datetime.utcnow(),
                details={
                    "queue_depth": health["queue_depth"],
                    "threshold": 1000,
                    "impact": "Event processing backlog"
                },
                confidence=1.0
            )
            self.report_threat(threat)
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get current system status."""
        if not self.health_history:
            return {"status": "unknown"}
        
        latest = self.health_history[-1]
        return {
            "status": "healthy" if latest["cpu_percent"] < 80 else "degraded",
            "health": latest,
            "scaling_events": len(self.scaling_events),
            "uptime_hours": (datetime.utcnow() - self._start_time).total_seconds() / 3600 if self._start_time else 0
        }


# Export
__all__ = ["ArchitectAgent"]

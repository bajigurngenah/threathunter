"""
ThreatHunter - Main Application
Entry point for the threat detection platform.
"""

import asyncio
import argparse
import logging
import sys
from datetime import datetime

from core import DetectionEngine
from agents.scout import ScoutAgent
from agents.sentinel import SentinelAgent
from agents.phantom import PhantomAgent
from agents.oracle import OracleAgent
from agents.commander import CommanderAgent
from agents.architect import ArchitectAgent

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("threathunter")


class ThreatHunter:
    """Main ThreatHunter application."""
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.engine = DetectionEngine()
        self._setup_agents()
    
    def _setup_agents(self):
        """Initialize all agents."""
        # Scout - Network Analysis
        scout = ScoutAgent(self.engine, self.config.get("scout", {}))
        self.engine.register_agent("scout", scout)
        
        # Sentinel - Endpoint Protection
        sentinel = SentinelAgent(self.engine, self.config.get("sentinel", {}))
        self.engine.register_agent("sentinel", sentinel)
        
        # Phantom - Memory Forensics
        phantom = PhantomAgent(self.engine, self.config.get("phantom", {}))
        self.engine.register_agent("phantom", phantom)
        
        # Oracle - Threat Intelligence
        oracle = OracleAgent(self.engine, self.config.get("oracle", {}))
        self.engine.register_agent("oracle", oracle)
        
        # Commander - Incident Response
        commander = CommanderAgent(self.engine, self.config.get("commander", {}))
        self.engine.register_agent("commander", commander)
        
        # Architect - System Optimization
        architect = ArchitectAgent(self.engine, self.config.get("architect", {}))
        self.engine.register_agent("architect", architect)
        
        logger.info("All agents initialized")
    
    async def start(self, agents: list = None):
        """Start the platform."""
        logger.info("=" * 60)
        logger.info("🛡️  ThreatHunter - AI-Powered Threat Detection")
        logger.info("=" * 60)
        logger.info(f"Starting at {datetime.utcnow().isoformat()}")
        logger.info(f"Agents: {', '.join(self.engine.agents.keys())}")
        logger.info("=" * 60)
        
        await self.engine.start(agents)
    
    async def stop(self):
        """Stop the platform."""
        logger.info("Stopping ThreatHunter...")
        await self.engine.stop()
        logger.info("ThreatHunter stopped")
    
    def status(self) -> dict:
        """Get platform status."""
        return self.engine.get_status()
    
    def threats(self, level: str = None):
        """Get detected threats."""
        from core import ThreatLevel
        if level:
            return self.engine.get_threats(ThreatLevel(level))
        return self.engine.get_threats()


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="ThreatHunter - AI-Powered Threat Detection")
    parser.add_argument("action", choices=["start", "status", "threats"],
                       help="Action to perform")
    parser.add_argument("--agents", nargs="+", help="Specific agents to run")
    parser.add_argument("--config", help="Path to config file")
    parser.add_argument("--duration", type=int, default=0,
                       help="Run duration in seconds (0 for infinite)")
    
    args = parser.parse_args()
    
    # Load config
    config = {}
    if args.config:
        import yaml
        with open(args.config) as f:
            config = yaml.safe_load(f)
    
    # Create platform
    platform = ThreatHunter(config)
    
    if args.action == "start":
        try:
            if args.duration > 0:
                # Run for specified duration
                await asyncio.wait_for(
                    platform.start(args.agents),
                    timeout=args.duration
                )
            else:
                # Run indefinitely
                await platform.start(args.agents)
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
        finally:
            await platform.stop()
    
    elif args.action == "status":
        import json
        print(json.dumps(platform.status(), indent=2))
    
    elif args.action == "threats":
        import json
        threats = platform.threats()
        print(json.dumps([t.to_dict() for t in threats], indent=2))


if __name__ == "__main__":
    asyncio.run(main())

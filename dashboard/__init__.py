"""
ThreatHunter - Web Dashboard
Real-time monitoring and visualization.
"""

from datetime import datetime
from typing import Dict, Any
import json


DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ThreatHunter - Security Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #0a0a0a; color: #e0e0e0; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
        .logo { font-size: 28px; font-weight: bold; color: #00ff88; }
        .status-badge { padding: 8px 16px; border-radius: 20px; font-size: 14px; }
        .status-active { background: #00ff8822; color: #00ff88; border: 1px solid #00ff88; }
        
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: #1a1a1a; border: 1px solid #333; border-radius: 12px; padding: 24px; }
        .stat-label { font-size: 12px; color: #888; text-transform: uppercase; letter-spacing: 1px; }
        .stat-value { font-size: 36px; font-weight: bold; margin: 8px 0; }
        .stat-change { font-size: 13px; }
        .stat-up { color: #00ff88; }
        .stat-down { color: #ff4444; }
        
        .agents-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 30px; }
        .agent-card { background: #1a1a1a; border: 1px solid #333; border-radius: 12px; padding: 20px; }
        .agent-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
        .agent-name { font-size: 16px; font-weight: 600; }
        .agent-status { width: 10px; height: 10px; border-radius: 50%; background: #00ff88; }
        .agent-metrics { display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px; }
        .agent-metric { font-size: 12px; }
        .agent-metric-label { color: #888; }
        .agent-metric-value { font-weight: 600; }
        
        .threats-section { background: #1a1a1a; border: 1px solid #333; border-radius: 12px; padding: 24px; }
        .threats-header { display: flex; justify-content: space-between; margin-bottom: 20px; }
        .threat-row { display: grid; grid-template-columns: 80px 2fr 1fr 1fr 100px; padding: 12px 0; border-bottom: 1px solid #222; align-items: center; }
        .threat-level { padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600; }
        .level-critical { background: #ff444422; color: #ff4444; border: 1px solid #ff4444; }
        .level-high { background: #ff880022; color: #ff8800; border: 1px solid #ff8800; }
        .level-medium { background: #ffcc0022; color: #ffcc00; border: 1px solid #ffcc00; }
        .level-low { background: #00ccff22; color: #00ccff; border: 1px solid #00ccff; }
        
        .chart-container { background: #1a1a1a; border: 1px solid #333; border-radius: 12px; padding: 24px; margin-bottom: 30px; }
        .chart-placeholder { height: 200px; background: linear-gradient(180deg, #00ff8811 0%, transparent 100%); border-radius: 8px; position: relative; }
        .chart-line { position: absolute; bottom: 0; left: 0; right: 0; height: 2px; background: #00ff88; }
        
        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🛡️ ThreatHunter</div>
            <div class="status-badge status-active">● SYSTEM ACTIVE</div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Threats Detected</div>
                <div class="stat-value" style="color: #ff4444;">2,847</div>
                <div class="stat-change stat-up">↑ 12% from yesterday</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Events Processed</div>
                <div class="stat-value" style="color: #00ccff;">14.2M</div>
                <div class="stat-change stat-up">↑ 8% from yesterday</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Mean Time to Detect</div>
                <div class="stat-value" style="color: #00ff88;">47ms</div>
                <div class="stat-change stat-down">↓ 15% improvement</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Active Incidents</div>
                <div class="stat-value" style="color: #ff8800;">23</div>
                <div class="stat-change stat-down">↓ 5 resolved today</div>
            </div>
        </div>
        
        <div class="chart-container">
            <h3 style="margin-bottom: 16px;">Threat Activity (24h)</h3>
            <div class="chart-placeholder">
                <div class="chart-line"></div>
            </div>
        </div>
        
        <h3 style="margin-bottom: 16px;">AI Agents</h3>
        <div class="agents-grid">
            <div class="agent-card">
                <div class="agent-header">
                    <div class="agent-name">🔍 Scout</div>
                    <div class="agent-status"></div>
                </div>
                <div class="agent-metrics">
                    <div class="agent-metric">
                        <div class="agent-metric-label">Threats</div>
                        <div class="agent-metric-value">847</div>
                    </div>
                    <div class="agent-metric">
                        <div class="agent-metric-label">Events/sec</div>
                        <div class="agent-metric-value">45.2K</div>
                    </div>
                    <div class="agent-metric">
                        <div class="agent-metric-label">Uptime</div>
                        <div class="agent-metric-value">99.99%</div>
                    </div>
                    <div class="agent-metric">
                        <div class="agent-metric-label">Latency</div>
                        <div class="agent-metric-value">12ms</div>
                    </div>
                </div>
            </div>
            
            <div class="agent-card">
                <div class="agent-header">
                    <div class="agent-name">🛡️ Sentinel</div>
                    <div class="agent-status"></div>
                </div>
                <div class="agent-metrics">
                    <div class="agent-metric">
                        <div class="agent-metric-label">Endpoints</div>
                        <div class="agent-metric-value">1,247</div>
                    </div>
                    <div class="agent-metric">
                        <div class="agent-metric-label">Alerts</div>
                        <div class="agent-metric-value">328</div>
                    </div>
                    <div class="agent-metric">
                        <div class="agent-metric-label">Uptime</div>
                        <div class="agent-metric-value">99.97%</div>
                    </div>
                    <div class="agent-metric">
                        <div class="agent-metric-label">Latency</div>
                        <div class="agent-metric-value">8ms</div>
                    </div>
                </div>
            </div>
            
            <div class="agent-card">
                <div class="agent-header">
                    <div class="agent-name">👻 Phantom</div>
                    <div class="agent-status"></div>
                </div>
                <div class="agent-metrics">
                    <div class="agent-metric">
                        <div class="agent-metric-label">Scans</div>
                        <div class="agent-metric-value">15.8K</div>
                    </div>
                    <div class="agent-metric">
                        <div class="agent-metric-label">Rootkits</div>
                        <div class="agent-metric-value">12</div>
                    </div>
                    <div class="agent-metric">
                        <div class="agent-metric-label">Uptime</div>
                        <div class="agent-metric-value">99.99%</div>
                    </div>
                    <div class="agent-metric">
                        <div class="agent-metric-label">Latency</div>
                        <div class="agent-metric-value">45ms</div>
                    </div>
                </div>
            </div>
            
            <div class="agent-card">
                <div class="agent-header">
                    <div class="agent-name">🔮 Oracle</div>
                    <div class="agent-status"></div>
                </div>
                <div class="agent-metrics">
                    <div class="agent-metric">
                        <div class="agent-metric-label">IOCs</div>
                        <div class="agent-metric-value">2.4M</div>
                    </div>
                    <div class="agent-metric">
                        <div class="agent-metric-label">Matches</div>
                        <div class="agent-metric-value">8,421</div>
                    </div>
                    <div class="agent-metric">
                        <div class="agent-metric-label">Uptime</div>
                        <div class="agent-metric-value">99.95%</div>
                    </div>
                    <div class="agent-metric">
                        <div class="agent-metric-label">Latency</div>
                        <div class="agent-metric-value">23ms</div>
                    </div>
                </div>
            </div>
            
            <div class="agent-card">
                <div class="agent-header">
                    <div class="agent-name">⚡ Commander</div>
                    <div class="agent-status"></div>
                </div>
                <div class="agent-metrics">
                    <div class="agent-metric">
                        <div class="agent-metric-label">Incidents</div>
                        <div class="agent-metric-value">1,247</div>
                    </div>
                    <div class="agent-metric">
                        <div class="agent-metric-label">Resolved</div>
                        <div class="agent-metric-value">1,224</div>
                    </div>
                    <div class="agent-metric">
                        <div class="agent-metric-label">Uptime</div>
                        <div class="agent-metric-value">99.99%</div>
                    </div>
                    <div class="agent-metric">
                        <div class="agent-metric-label">MTTR</div>
                        <div class="agent-metric-value">2.3s</div>
                    </div>
                </div>
            </div>
            
            <div class="agent-card">
                <div class="agent-header">
                    <div class="agent-name">🏗️ Architect</div>
                    <div class="agent-status"></div>
                </div>
                <div class="agent-metrics">
                    <div class="agent-metric">
                        <div class="agent-metric-label">CPU</div>
                        <div class="agent-metric-value">45%</div>
                    </div>
                    <div class="agent-metric">
                        <div class="agent-metric-label">Memory</div>
                        <div class="agent-metric-value">62%</div>
                    </div>
                    <div class="agent-metric">
                        <div class="agent-metric-label">Uptime</div>
                        <div class="agent-metric-value">99.99%</div>
                    </div>
                    <div class="agent-metric">
                        <div class="agent-metric-label">Scaling</div>
                        <div class="agent-metric-value">Auto</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="threats-section">
            <div class="threats-header">
                <h3>Recent Threats</h3>
                <span style="color: #888;">Last 24 hours</span>
            </div>
            
            <div class="threat-row" style="color: #888; font-size: 12px;">
                <div>SEVERITY</div>
                <div>THREAT NAME</div>
                <div>SOURCE</div>
                <div>CONFIDENCE</div>
                <div>STATUS</div>
            </div>
            
            <div class="threat-row">
                <div><span class="threat-level level-critical">CRITICAL</span></div>
                <div>C2 Beaconing Detected</div>
                <div>Scout Agent</div>
                <div>95%</div>
                <div style="color: #ff4444;">Active</div>
            </div>
            
            <div class="threat-row">
                <div><span class="threat-level level-critical">CRITICAL</span></div>
                <div>Ransomware Behavior</div>
                <div>Sentinel Agent</div>
                <div>99%</div>
                <div style="color: #ff8800;">Responding</div>
            </div>
            
            <div class="threat-row">
                <div><span class="threat-level level-high">HIGH</span></div>
                <div>SSDT Hook Detected</div>
                <div>Phantom Agent</div>
                <div>97%</div>
                <div style="color: #00ff88;">Mitigated</div>
            </div>
            
            <div class="threat-row">
                <div><span class="threat-level level-high">HIGH</span></div>
                <div>Data Exfiltration Attempt</div>
                <div>Scout Agent</div>
                <div>88%</div>
                <div style="color: #ff8800;">Investigating</div>
            </div>
            
            <div class="threat-row">
                <div><span class="threat-level level-medium">MEDIUM</span></div>
                <div>Suspicious PowerShell</div>
                <div>Sentinel Agent</div>
                <div>85%</div>
                <div style="color: #00ff88;">Resolved</div>
            </div>
        </div>
        
        <div class="footer">
            ThreatHunter v1.0.0 | Powered by 6 AI Agents | Real-time Threat Detection
        </div>
    </div>
    
    <script>
        // Auto-refresh every 30 seconds
        setTimeout(() => location.reload(), 30000);
    </script>
</body>
</html>
"""


def get_dashboard() -> str:
    """Return the dashboard HTML."""
    return DASHBOARD_HTML


def get_metrics_json(status: Dict[str, Any]) -> str:
    """Return metrics as JSON."""
    return json.dumps(status, indent=2)

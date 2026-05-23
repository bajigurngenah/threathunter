"""
ThreatHunter - Real API Integrations
Connect to actual threat intelligence services.
"""

import asyncio
import aiohttp
import hashlib
from typing import List, Dict, Any, Optional
from datetime import datetime


class VirusTotalAPI:
    """VirusTotal API integration for file/hash/URL analysis."""
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"x-apikey": api_key}
    
    async def check_hash(self, file_hash: str) -> Dict[str, Any]:
        """Check file hash against VirusTotal database."""
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.BASE_URL}/files/{file_hash}",
                headers=self.headers
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    attrs = data.get("data", {}).get("attributes", {})
                    return {
                        "hash": file_hash,
                        "malicious": attrs.get("last_analysis_stats", {}).get("malicious", 0),
                        "suspicious": attrs.get("last_analysis_stats", {}).get("suspicious", 0),
                        "undetected": attrs.get("last_analysis_stats", {}).get("undetected", 0),
                        "threat_name": attrs.get("popular_threat_classification", {}).get("suggested_threat_label"),
                        "first_seen": attrs.get("first_submission_date"),
                        "tags": attrs.get("tags", [])
                    }
                return {"hash": file_hash, "error": f"HTTP {resp.status}"}
    
    async def check_url(self, url: str) -> Dict[str, Any]:
        """Check URL against VirusTotal."""
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.BASE_URL}/urls/{url_id}",
                headers=self.headers
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    attrs = data.get("data", {}).get("attributes", {})
                    return {
                        "url": url,
                        "malicious": attrs.get("last_analysis_stats", {}).get("malicious", 0),
                        "categories": attrs.get("categories", {}),
                        "reputation": attrs.get("reputation", 0)
                    }
                return {"url": url, "error": f"HTTP {resp.status}"}
    
    async def check_ip(self, ip: str) -> Dict[str, Any]:
        """Check IP address reputation."""
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.BASE_URL}/ip_addresses/{ip}",
                headers=self.headers
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    attrs = data.get("data", {}).get("attributes", {})
                    return {
                        "ip": ip,
                        "country": attrs.get("country"),
                        "as_owner": attrs.get("as_owner"),
                        "reputation": attrs.get("reputation", 0),
                        "malicious": attrs.get("last_analysis_stats", {}).get("malicious", 0),
                        "tags": attrs.get("tags", [])
                    }
                return {"ip": ip, "error": f"HTTP {resp.status}"}


class ShodanAPI:
    """Shodan API for internet-connected device intelligence."""
    
    BASE_URL = "https://api.shodan.io"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
    
    async def host_info(self, ip: str) -> Dict[str, Any]:
        """Get detailed host information."""
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.BASE_URL}/shodan/host/{ip}?key={self.api_key}"
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        "ip": ip,
                        "ports": data.get("ports", []),
                        "os": data.get("os"),
                        "vulns": data.get("vulns", []),
                        "hostnames": data.get("hostnames", []),
                        "org": data.get("org"),
                        "isp": data.get("isp"),
                        "last_update": data.get("last_update")
                    }
                return {"ip": ip, "error": f"HTTP {resp.status}"}
    
    async def search_vulns(self, query: str) -> List[Dict]:
        """Search for vulnerabilities."""
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.BASE_URL}/shodan/host/search?key={self.api_key}&query={query}"
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("matches", [])
                return []


class AbuseIPDB:
    """AbuseIPDB for IP reputation and abuse reports."""
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"Key": api_key, "Accept": "application/json"}
    
    async def check_ip(self, ip: str, max_age_days: int = 90) -> Dict[str, Any]:
        """Check IP address for abuse reports."""
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.BASE_URL}/check",
                headers=self.headers,
                params={"ipAddress": ip, "maxAgeInDays": max_age_days}
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    d = data.get("data", {})
                    return {
                        "ip": ip,
                        "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
                        "total_reports": d.get("totalReports", 0),
                        "country_code": d.get("countryCode"),
                        "isp": d.get("isp"),
                        "domain": d.get("domain"),
                        "is_tor": d.get("isTor", False),
                        "is_whitelisted": d.get("isWhitelisted", False)
                    }
                return {"ip": ip, "error": f"HTTP {resp.status}"}


class OTXAlienVault:
    """AlienVault OTX for threat intelligence."""
    
    BASE_URL = "https://otx.alienvault.com/api/v1"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"X-OTX-API-KEY": api_key}
    
    async def get_pulse(self, indicator: str, indicator_type: str = "IPv4") -> Dict[str, Any]:
        """Get threat intelligence for an indicator."""
        section_map = {
            "IPv4": "general",
            "domain": "general",
            "file": "general",
            "url": "general"
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.BASE_URL}/indicators/{indicator_type}/{indicator}/{section_map.get(indicator_type, 'general')}",
                headers=self.headers
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        "indicator": indicator,
                        "type": indicator_type,
                        "pulse_count": data.get("pulse_info", {}).get("count", 0),
                        "reputation": data.get("reputation", 0),
                        "country": data.get("country_name"),
                        "validation": data.get("validation", [])
                    }
                return {"indicator": indicator, "error": f"HTTP {resp.status}"}


class ThreatIntelManager:
    """Unified threat intelligence manager."""
    
    def __init__(self, config: Dict[str, str] = None):
        config = config or {}
        self.virustotal = VirusTotalAPI(config.get("virustotal_key", ""))
        self.shodan = ShodanAPI(config.get("shodan_key", ""))
        self.abuseipdb = AbuseIPDB(config.get("abuseipdb_key", ""))
        self.otx = OTXAlienVault(config.get("otx_key", ""))
        self.cache = {}
    
    async def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """Enrich IP with all available threat intel."""
        if ip in self.cache:
            return self.cache[ip]
        
        results = await asyncio.gather(
            self.virustotal.check_ip(ip),
            self.abuseipdb.check_ip(ip),
            self.otx.get_pulse(ip, "IPv4"),
            return_exceptions=True
        )
        
        enriched = {
            "ip": ip,
            "virustotal": results[0] if not isinstance(results[0], Exception) else {},
            "abuseipdb": results[1] if not isinstance(results[1], Exception) else {},
            "otx": results[2] if not isinstance(results[2], Exception) else {},
            "enriched_at": datetime.utcnow().isoformat()
        }
        
        self.cache[ip] = enriched
        return enriched
    
    async def enrich_hash(self, file_hash: str) -> Dict[str, Any]:
        """Enrich file hash with threat intel."""
        if file_hash in self.cache:
            return self.cache[file_hash]
        
        result = await self.virustotal.check_hash(file_hash)
        
        enriched = {
            "hash": file_hash,
            "virustotal": result,
            "enriched_at": datetime.utcnow().isoformat()
        }
        
        self.cache[file_hash] = enriched
        return enriched
    
    async def bulk_check(self, indicators: List[Dict[str, str]]) -> List[Dict]:
        """Bulk check multiple indicators."""
        results = []
        for indicator in indicators:
            if indicator["type"] == "ip":
                result = await self.enrich_ip(indicator["value"])
            elif indicator["type"] == "hash":
                result = await self.enrich_hash(indicator["value"])
            else:
                result = {"indicator": indicator["value"], "error": "unsupported type"}
            results.append(result)
        return results


# Export
__all__ = [
    "VirusTotalAPI",
    "ShodanAPI", 
    "AbuseIPDB",
    "OTXAlienVault",
    "ThreatIntelManager"
]

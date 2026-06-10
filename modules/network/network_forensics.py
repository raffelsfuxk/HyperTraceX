#!/usr/bin/env python3
"""FORENSIX Network Forensics - Analyze network traffic and connections."""

import os
import re
import json
import subprocess
from datetime import datetime
from typing import Dict, List, Optional
from collections import defaultdict

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="FORENSIX"):
        return logging.getLogger(name)


class NetworkForensics:
    """
    Network Forensic Analysis Module.
    
    Features:
        - PCAP analysis
        - DNS cache parsing
        - ARP table analysis
        - Active connections enumeration
        - Firewall log parsing
        - Network configuration extraction
    """
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.results: Dict[str, List] = {
            "connections": [],
            "dns_cache": [],
            "arp_table": [],
            "firewall_rules": [],
            "network_config": []
        }
    
    def analyze_pcap(self, pcap_file: str, filter_str: str = "") -> List[Dict]:
        """
        Analyze PCAP file using tshark.
        
        Args:
            pcap_file: Path to PCAP file
            filter_str: Display filter (e.g., "http", "dns", "tcp.port==443")
        
        Returns:
            List of packet summaries
        """
        packets = []
        
        if not os.path.exists(pcap_file):
            self.logger.error(f"PCAP file not found: {pcap_file}")
            return packets
        
        print(f"\n[*] Analyzing PCAP: {os.path.basename(pcap_file)}")
        
        try:
            cmd = ["tshark", "-r", pcap_file, "-T", "fields",
                   "-e", "frame.time",
                   "-e", "ip.src",
                   "-e", "ip.dst",
                   "-e", "tcp.srcport",
                   "-e", "tcp.dstport",
                   "-e", "udp.srcport",
                   "-e", "udp.dstport",
                   "-e", "dns.qry.name",
                   "-e", "http.host",
                   "-e", "http.request.uri",
                   "-e", "tls.handshake.extensions_server_name"]
            
            if filter_str:
                cmd.extend(["-Y", filter_str])
            
            cmd.extend(["-c", "1000"])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            for line in result.stdout.splitlines():
                if line.strip():
                    fields = line.split('\t')
                    if len(fields) >= 3:
                        packet = {
                            "timestamp": fields[0],
                            "src_ip": fields[1] if len(fields) > 1 else "",
                            "dst_ip": fields[2] if len(fields) > 2 else "",
                            "protocol": "TCP" if fields[3] else "UDP" if fields[5] else "OTHER",
                            "src_port": fields[3] if len(fields) > 3 else fields[5] if len(fields) > 5 else "",
                            "dst_port": fields[4] if len(fields) > 4 else fields[6] if len(fields) > 6 else "",
                            "dns_query": fields[7] if len(fields) > 7 else "",
                            "http_host": fields[8] if len(fields) > 8 else "",
                            "http_uri": fields[9] if len(fields) > 9 else "",
                            "tls_sni": fields[10] if len(fields) > 10 else ""
                        }
                        packets.append(packet)
            
            print(f"[+] Extracted {len(packets)} packets")
            
        except FileNotFoundError:
            self.logger.warning("tshark not installed. Install: sudo apt install tshark")
        except Exception as e:
            self.logger.error(f"PCAP analysis failed: {e}")
        
        return packets
    
    def parse_dns_cache(self, cache_source: str) -> List[Dict]:
        """
        Parse DNS cache from various sources.
        
        Args:
            cache_source: Path to DNS cache file or 'live' for live system
        """
        entries = []
        
        if cache_source == "live":
            try:
                result = subprocess.run(
                    ["systemd-resolve", "--statistics"],
                    capture_output=True, text=True
                )
                entries.append({"source": "systemd-resolved", "raw": result.stdout})
            except:
                pass
        
        elif os.path.exists(cache_source):
            try:
                with open(cache_source, 'r', errors='ignore') as f:
                    content = f.read()
                
                dns_pattern = re.compile(
                    r'(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})|'
                    r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\s+(\d+)\s+([A-Z]+)',
                    re.MULTILINE
                )
                
                for match in dns_pattern.finditer(content):
                    if match.group(2):
                        entries.append({
                            "domain": match.group(2),
                            "ttl": match.group(3),
                            "type": match.group(4)
                        })
            except Exception as e:
                self.logger.error(f"DNS cache parsing failed: {e}")
        
        self.results["dns_cache"] = entries
        return entries
    
    def get_active_connections(self) -> List[Dict]:
        """Get active network connections from live system."""
        connections = []
        
        try:
            result = subprocess.run(
                ["ss", "-tunap"],
                capture_output=True, text=True
            )
            
            for line in result.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    conn = {
                        "protocol": parts[0],
                        "recv_q": parts[1],
                        "send_q": parts[2],
                        "local": parts[3],
                        "remote": parts[4],
                        "state": parts[5] if len(parts) > 5 else "",
                        "process": parts[6] if len(parts) > 6 else ""
                    }
                    connections.append(conn)
            
        except Exception as e:
            self.logger.error(f"Connection scan failed: {e}")
        
        self.results["connections"] = connections
        return connections
    
    def parse_arp_table(self) -> List[Dict]:
        """Parse ARP table for MAC-IP mappings."""
        entries = []
        
        try:
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True, text=True
            )
            
            for line in result.stdout.splitlines():
                match = re.match(
                    r'.*?\((\d+\.\d+\.\d+\.\d+)\).*?at\s+([0-9a-fA-F:]{17})',
                    line
                )
                if match:
                    entries.append({
                        "ip": match.group(1),
                        "mac": match.group(2)
                    })
            
        except Exception as e:
            self.logger.error(f"ARP parsing failed: {e}")
        
        self.results["arp_table"] = entries
        return entries
    
    def extract_firewall_rules(self, rules_source: str = "live") -> List[Dict]:
        """Extract firewall rules."""
        rules = []
        
        try:
            if rules_source == "live":
                # iptables
                result = subprocess.run(
                    ["iptables", "-L", "-n", "-v"],
                    capture_output=True, text=True
                )
                rules.append({"source": "iptables", "raw": result.stdout})
                
                # ufw
                result = subprocess.run(
                    ["ufw", "status", "verbose"],
                    capture_output=True, text=True
                )
                rules.append({"source": "ufw", "raw": result.stdout})
            else:
                if os.path.exists(rules_source):
                    with open(rules_source, 'r') as f:
                        rules.append({"source": rules_source, "raw": f.read()})
        except:
            pass
        
        self.results["firewall_rules"] = rules
        return rules
    
    def extract_network_config(self, config_source: str = "live") -> List[Dict]:
        """Extract network configuration."""
        config = []
        
        try:
            if config_source == "live":
                result = subprocess.run(
                    ["ip", "addr", "show"],
                    capture_output=True, text=True
                )
                config.append({"source": "ip_addr", "raw": result.stdout})
                
                result = subprocess.run(
                    ["ip", "route", "show"],
                    capture_output=True, text=True
                )
                config.append({"source": "ip_route", "raw": result.stdout})
                
                # DNS config
                if os.path.exists("/etc/resolv.conf"):
                    with open("/etc/resolv.conf", 'r') as f:
                        config.append({"source": "resolv.conf", "raw": f.read()})
        except:
            pass
        
        self.results["network_config"] = config
        return config
    
    def find_suspicious_connections(self) -> List[Dict]:
        """Identify potentially suspicious network connections."""
        suspicious = []
        
        suspicious_ports = [4444, 1337, 31337, 6666, 6667, 8080, 8888, 9001]
        suspicious_keywords = ["c2", "beacon", "reverse", "shell", "meterpreter"]
        
        for conn in self.results.get("connections", []):
            remote = conn.get("remote", "")
            
            for port in suspicious_ports:
                if f":{port}" in remote:
                    suspicious.append({
                        "connection": conn,
                        "reason": f"Suspicious port: {port}"
                    })
            
            process = conn.get("process", "").lower()
            for keyword in suspicious_keywords:
                if keyword in process:
                    suspicious.append({
                        "connection": conn,
                        "reason": f"Suspicious process keyword: {keyword}"
                    })
        
        return suspicious
    
    def get_statistics(self) -> Dict:
        """Get network analysis statistics."""
        return {
            "total_connections": len(self.results.get("connections", [])),
            "dns_entries": len(self.results.get("dns_cache", [])),
            "arp_entries": len(self.results.get("arp_table", [])),
            "suspicious_found": len(self.find_suspicious_connections())
        }
    
    def display_summary(self):
        """Display network analysis summary."""
        stats = self.get_statistics()
        
        print(f"\n[Network Forensics Summary]")
        print(f"{'='*50}")
        print(f"  Active Connections: {stats['total_connections']}")
        print(f"  DNS Cache Entries:  {stats['dns_entries']}")
        print(f"  ARP Table Entries:  {stats['arp_entries']}")
        print(f"  Suspicious Found:   {stats['suspicious_found']}")
        print(f"{'='*50}\n")
    
    def export_json(self, output_file: str):
        """Export results to JSON."""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=4, default=str)
        print(f"[+] Network analysis exported: {output_file}")

"""
detector.py
Core detection engine that inspects network packets against rules and signatures.
"""

import time
from collections import defaultdict
from scapy.all import IP, TCP, UDP
from signatures import BLACKLISTED_IPS, SUSPICIOUS_PORTS, RULES
from logger import IDSLogger

class IntrusionDetector:
    def __init__(self):
        self.logger = IDSLogger()
        self.alerts_generated = 0
        self.packets_analyzed = 0
        self.alerts = []
        
        # State tracking for behavioral rules
        self.syn_counts = defaultdict(list)
        self.port_access = defaultdict(set)
        
        # Traffic statistics for visualization/summary
        self.attack_stats = defaultdict(int)

    def trigger_alert(self, severity, src_ip, attack_type, details):
        """Helper to invoke the logger and increment statistics."""
        self.logger.log_alert(severity, src_ip, attack_type, details)
        self.alerts_generated += 1
        self.attack_stats[attack_type] += 1
        
        alert_data = {
            "id": self.alerts_generated,
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "severity": severity,
            "source_ip": src_ip,
            "type": attack_type,
            "details": details
        }
        self.alerts.append(alert_data)
        
        # Keep the latest 100 alerts to prevent memory explosion
        if len(self.alerts) > 100:
            self.alerts.pop(0)

    def analyze_packet(self, packet):
        """
        Callback function for packet capture. Inspects individual packets.
        """
        try:
            self.packets_analyzed += 1
            # We strictly analyze IP packets
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # RULE 1: Blacklisted IP Detection (Signature-based)
                if src_ip in BLACKLISTED_IPS or dst_ip in BLACKLISTED_IPS:
                    bad_ip = src_ip if src_ip in BLACKLISTED_IPS else dst_ip
                    self.trigger_alert("HIGH", src_ip, "Blacklisted IP", f"Traffic involving blacklisted IP {bad_ip}")
                
                # Further inspect TCP headers
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    dst_port = tcp_layer.dport
                    
                    # RULE 2: Suspicious Port Access (Signature-based)
                    if dst_port in SUSPICIOUS_PORTS:
                        self.trigger_alert("MEDIUM", src_ip, "Suspicious Port Access", f"Targeted port {dst_port}")
                    
                    # RULE 3: SYN Flood Detection (Behavioral/Anomaly)
                    # The "S" flag represents a SYN packet
                    if tcp_layer.flags == "S":
                        current_time = time.time()
                        self.syn_counts[src_ip].append(current_time)
                        
                        # Apply a sliding window constraint: Remove older requests
                        self.syn_counts[src_ip] = [
                            t for t in self.syn_counts[src_ip] 
                            if current_time - t <= RULES["time_window"]
                        ]
                        
                        # Check threshold
                        if len(self.syn_counts[src_ip]) > RULES["syn_flood_threshold"]:
                            self.trigger_alert("HIGH", src_ip, "SYN Flood", f"Exceeded SYN threshold in {RULES['time_window']}s")
                            # Clear recent history to avoid spamming the console 
                            self.syn_counts[src_ip].clear() 
                    
                    # RULE 4: Port Scan Detection (Behavioral/Anomaly)
                    self.port_access[src_ip].add(dst_port)
                    
                    if len(self.port_access[src_ip]) > RULES["port_scan_threshold"]:
                        self.trigger_alert("HIGH", src_ip, "Port Scan", f"Accessed {len(self.port_access[src_ip])} distinct ports")
                        self.port_access[src_ip].clear()

        except Exception as e:
            # Drop malformed packets silently to strictly maintain lightweight performance
            pass

    def get_summary(self):
        """Returns a summary of detected attacks."""
        return {
            "total_alerts": self.alerts_generated,
            "total_packets": self.packets_analyzed,
            "attack_stats": dict(self.attack_stats)
        }

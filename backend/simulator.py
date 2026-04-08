import time
import random
import threading
from scapy.all import IP, TCP, UDP
from signatures import BLACKLISTED_IPS, SUSPICIOUS_PORTS

class TrafficSimulator:
    def __init__(self, detector):
        self.detector = detector
        self.is_running = False

    def start(self):
        self.is_running = True
        self.thread = threading.Thread(target=self._simulate_loop)
        self.thread.daemon = True
        self.thread.start()
        print("[*] Started internal traffic simulator.")

    def stop(self):
        self.is_running = False
        print("[*] Stopped internal traffic simulator.")

    def _simulate_loop(self):
        # Generate some synthetic traffic every 0.1 to 1.5 seconds
        while self.is_running:
            time.sleep(random.uniform(0.1, 1.5))
            
            # 80% normal traffic, 20% malicious
            if random.random() < 0.8:
                self._generate_normal_traffic()
            else:
                self._generate_malicious_traffic()

    def _generate_normal_traffic(self):
        # Benign web traffic
        src = f"192.168.1.{random.randint(2, 254)}"
        dst = "8.8.8.8"
        sport = random.randint(1024, 65535)
        dport = random.choice([80, 443])
        packet = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="A")
        self.detector.analyze_packet(packet)

    def _generate_malicious_traffic(self):
        attack_type = random.choice(["blacklisted", "suspicious_port", "syn_flood", "port_scan"])
        src = f"10.0.0.{random.randint(1, 100)}"
        dst = "192.168.1.10"
        
        if attack_type == "blacklisted":
            src = random.choice(BLACKLISTED_IPS)
            packet = IP(src=src, dst=dst)/TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
            self.detector.analyze_packet(packet)
            
        elif attack_type == "suspicious_port":
            dport = random.choice(SUSPICIOUS_PORTS)
            packet = IP(src=src, dst=dst)/TCP(sport=random.randint(1024, 65535), dport=dport, flags="S")
            self.detector.analyze_packet(packet)
            
        elif attack_type == "syn_flood":
            # Fire a burst of SYN packets
            for _ in range(25): # Assuming threshold is lower than this
                packet = IP(src=src, dst=dst)/TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
                self.detector.analyze_packet(packet)
                
        elif attack_type == "port_scan":
            # Iterate through many ports
            for dport in range(20, 50):
                packet = IP(src=src, dst=dst)/TCP(sport=random.randint(1024, 65535), dport=dport, flags="S")
                self.detector.analyze_packet(packet)

import time
from scapy.all import IP, TCP, UDP

class TrafficProcessor:
    def __init__(self):
        # This will hold our "Feature Vector"
        self.packet_count = 0
        self.total_bytes = 0
        self.unique_ips = set()
        self.start_time = time.time()

    def process_packet(self, packet):
        """Extracts data from a single raw packet."""
        if packet.haslayer(IP):
            self.packet_count += 1
            self.total_bytes += len(packet)
            self.unique_ips.add(packet[IP].src)

    def get_features(self):
        """Calculates the final numbers for the ML model."""
        duration = time.time() - self.start_time
        if duration == 0: return None
        
        features = {
            "packet_rate": self.packet_count / duration,
            "avg_packet_size": self.total_bytes / self.packet_count if self.packet_count > 0 else 0,
            "unique_src_ips": len(self.unique_ips)
        }
        
        # Reset for the next window
        self.reset()
        return features

    def reset(self):
        self.packet_count = 0
        self.total_bytes = 0
        self.unique_ips = set()
        self.start_time = time.time()

# --- Test the Processor ---
if __name__ == "__main__":
    from scapy.all import sniff
    
    proc = TrafficProcessor()
    print("Collecting data for 5 seconds...")
    
    # Sniff for 5 seconds
    sniff(prn=proc.process_packet, timeout=5)
    
    stats = proc.get_features()
    print("\n--- Feature Vector Generated ---")
    for key, value in stats.items():
        print(f"{key}: {value:.2f}")
import time
from scapy.all import IP, TCP, UDP

class TrafficProcessor:
    def __init__(self):
        self.reset()

    def process_packet(self, packet):
        """Extracts data from a single raw packet."""
        if packet.haslayer(IP):
            self.packet_count += 1
            self.total_fwd_length += len(packet)
            
            # Capture the Destination Port from the first packet in the window
            if self.dest_port == 0:
                if packet.haslayer(TCP):
                    self.dest_port = packet[TCP].dport
                elif packet.haslayer(UDP):
                    self.dest_port = packet[UDP].dport

    def get_features(self):
        """Calculates the final numbers in the format the ML model expects."""
        duration = time.time() - self.start_time
        
        # Avoid division by zero
        if duration <= 0 or self.packet_count == 0:
            packet_rate = 0
        else:
            packet_rate = self.packet_count / duration
        
        # This list MUST match the order: [Port, Rate, Length]
        features = [
            float(self.dest_port),
            float(packet_rate),
            float(self.total_fwd_length)
        ]
        
        # Clear stats for the next 5-second window
        self.reset()
        return features

    def reset(self):
        """Restarts the counters."""
        self.packet_count = 0
        self.total_fwd_length = 0
        self.dest_port = 0
        self.start_time = time.time()
import time
from scapy.all import IP, TCP, UDP

class TrafficProcessor:
    def __init__(self):
        self.reset()

    def process_packet(self, packet):
        """
        Extracts raw packet data and updates window statistics.
        Focuses on Destination Port, Packet Count, and Payload Length.
        """
        if packet.haslayer(IP):
            self.packet_count += 1
            self.total_fwd_length += len(packet)
            
            # Capture port from the first packet in the 5-second window
            if self.dest_port == 0:
                if packet.haslayer(TCP):
                    self.dest_port = packet[TCP].dport
                elif packet.haslayer(UDP):
                    self.dest_port = packet[UDP].dport

    def get_features(self):
        """
        Calculates and returns the feature vector for model inference.
        Resets counters for the next window.
        """
        duration = time.time() - self.start_time
        
        # Calculate packet rate, avoiding division by zero
        packet_rate = self.packet_count / duration if duration > 0 else 0
        
        # Structure must match training: [Port, Rate, Length]
        features = [
            float(self.dest_port),
            float(packet_rate),
            float(self.total_fwd_length)
        ]
        
        self.reset()
        return features

    def reset(self):
        """Initializes/Resets the tracking variables for each capture window."""
        self.packet_count = 0
        self.total_fwd_length = 0
        self.dest_port = 0
        self.start_time = time.time()
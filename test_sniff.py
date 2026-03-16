from scapy.all import sniff

def simple_callback(packet):
    print(f"Packet Detected! Protocol: {packet.summary()}")

print("Starting sniffer... (Press Ctrl+C to stop)")
# This captures 10 packets
sniff(prn=simple_callback, count=10)
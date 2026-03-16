from scapy.all import sniff

def simple_callback(packet):
    print(f"Packet Detected! Protocol: {packet.summary()}")

print("Starting sniffer... (Press Ctrl+C to stop)")

sniff(prn=simple_callback, count=10)
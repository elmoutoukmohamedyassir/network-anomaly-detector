import joblib
import pandas as pd
import time
from scapy.all import sniff
from processor import TrafficProcessor


try:
    model = joblib.load('anomaly_model.joblib')
    print(" ML Model Loaded successfully.")
except:
    print(" Error: Could not find 'anomaly_model.joblib'. Run train_model.py first!")
    exit()

proc = TrafficProcessor()

def monitor_callback(packet):
    """Feeds every packet captured into our processor."""
    proc.process_packet(packet)

print("\n NETWORK GUARDIAN ACTIVE")
print("Monitoring your interface in 5-second windows...")
print("Press Ctrl+C to stop.\n")
print(f"{'TIME':<10} | {'PORT':<6} | {'PKT/S':<8} | {'LENGTH':<10} | {'STATUS'}")
print("-" * 60)

try:
    while True:
        # Sniff for 5 seconds
        sniff(prn=monitor_callback, timeout=5, store=0)
        
        # Get the numbers from our processor
        features = proc.get_features() # [port, rate, length]
        
        if features:
            # Prepare data for the model (must be a DataFrame with same columns)
            df_features = pd.DataFrame([features], columns=['Destination Port', 'Flow Packets/s', 'Total Length of Fwd Packets'])
            
            # Predict! (1 = Normal, -1 = Anomaly)
            prediction = model.predict(df_features)
            
            # Formatting the output
            current_time = time.strftime("%H:%M:%S")
            status = " SAFE" if prediction[0] == 1 else "  DANGER / ANOMALY"
            
            print(f"{current_time:<10} | {int(features[0]):<6} | {features[1]:<8.2f} | {features[2]:<10.0f} | {status}")

except KeyboardInterrupt:
    print("\n\n[!] Stopping the monitor. Stay safe!")
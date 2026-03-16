import joblib
import pandas as pd
import time
import os
from scapy.all import sniff
from processor import TrafficProcessor

def run_monitor():
    # Load the pre-trained Isolation Forest model
    model_file = 'anomaly_model.joblib'
    if not os.path.exists(model_file):
        print(f"Error: {model_file} not found. Please run train_model.py first.")
        return

    model = joblib.load(model_file)
    processor = TrafficProcessor()

    print("Network Anomaly Detector initialized.")
    print("Monitoring live traffic in 5-second intervals...")
    print(f"{'TIMESTAMP':<12} | {'PORT':<8} | {'PKTS/S':<10} | {'LENGTH':<10} | {'STATUS'}")
    print("-" * 65)

    try:
        while True:
            # Capture packets for a 5-second duration
            sniff(prn=processor.process_packet, timeout=5, store=0)
            
            # Extract features for prediction
            features = processor.get_features()
            
            # Prepare data for model inference
            df_features = pd.DataFrame([features], columns=[
                'Destination Port', 
                'Flow Packets/s', 
                'Total Length of Fwd Packets'
            ])
            
            # Inference: 1 for Normal, -1 for Anomaly
            prediction = model.predict(df_features)[0]
            
            timestamp = time.strftime("%H:%M:%S")
            status = "ANOMALY DETECTED" if prediction == -1 else "NORMAL"
            
            # Print formatted output
            print(f"{timestamp:<12} | {int(features[0]):<8} | {features[1]:<10.2f} | {features[2]:<10.0f} | {status}")

    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")

if __name__ == "__main__":
    run_monitor()
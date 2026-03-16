import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import os

data_path = os.path.join('data', 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv')

print("Reading data... this might take 10-20 seconds.")
df = pd.read_csv(data_path)

# 2. Clean column names (removing any hidden spaces)
df.columns = df.columns.str.strip()

# 3. Select the features we can actually capture with Scapy
# We use these 3 because they are the most "telling" for DDoS
features = ['Destination Port', 'Flow Packets/s', 'Total Length of Fwd Packets']

# 4. Data Cleaning (Crucial for ML)
X = df[features].dropna()
X = X.replace([float('inf'), float('-inf')], 0)

print(f"Training 'The Brain' on {len(X)} rows of network traffic...")

# 5. Initialize and Train
# contamination=0.1 means we expect 10% of the traffic to be 'anomalous'
model = IsolationForest(contamination=0.1, random_state=42)
model.fit(X)

# 6. Save the model
joblib.dump(model, 'anomaly_model.joblib')

print("---")
print(" SUCCESS: 'anomaly_model.joblib' has been created!")
print("You can now see it in your folder.")
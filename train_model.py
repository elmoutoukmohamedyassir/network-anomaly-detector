import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

# 1. Create a dummy dataset that mimics network traffic
# In a real scenario, you'd load 'cic_ids_2017.csv' here.
data = {
    'packet_rate': [2, 3, 1, 4, 100, 2, 5, 120, 3, 4],
    'avg_packet_size': [64, 128, 60, 130, 40, 66, 120, 38, 70, 135],
    'unique_src_ips': [1, 1, 1, 2, 50, 1, 2, 60, 1, 2]
}

df = pd.DataFrame(data)

# 2. Initialize the Isolation Forest
# contamination=0.2 means we expect about 20% of our training data to be "weird"
model = IsolationForest(contamination=0.2, random_state=42)

# 3. Train the model
# We only use the numbers, no labels needed!
model.fit(df)

# 4. Save the model so our 'processor.py' can use it later
joblib.dump(model, 'anomaly_model.joblib')

print(" Model trained and saved as 'anomaly_model.joblib'!")
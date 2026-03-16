# network-anomaly-detector

Real-time network traffic analysis and anomaly detection system using Python, Scapy, and Machine Learning


# AI-Powered Network Anomaly Detector 🛡️

An end-to-end Machine Learning pipeline designed to sniff real-time network traffic and identify potential security anomalies (e.g., DDoS patterns) using Unsupervised Learning.

## 📌 Project Overview

This project bridges the gap between Network Security and Data Analytics. Instead of relying on hard-coded rules, it uses an **Isolation Forest** model to establish a baseline of "normal" behavior and flags statistical outliers in real-time.

## 🛠️ Tech Stack

- **Language:** Python 3.x
- **Network Analysis:** Scapy (Live packet sniffing)
- **Machine Learning:** Scikit-Learn (Isolation Forest)
- **Data Handling:** Pandas & NumPy
- **Dataset:** CIC-IDS-2017 (Industry-standard benchmark for IDS)

## ⚙️ How it Works

1. **Feature Engineering:** The system extracts three core features from every 5-second window of traffic:
   - Destination Port
   - Flow Packets per Second
   - Total Forward Packet Length
2. **Training:** The model was trained on the Friday-DDoS subset of the CIC-IDS-2017 dataset to learn the specific signatures of high-intensity network attacks.
3. **Inference:** The `main.py` script captures live traffic, processes it through the `TrafficProcessor`, and uses the saved model (`.joblib`) to predict the status.

## 📊 Results

The detector successfully identifies high-volume traffic spikes as **Anomalies**, providing a visual alert in the terminal. This demonstrates the model's ability to distinguish between standard background traffic and "DDoS-like" intensity.

## 🚀 Future Improvements

- [ ] Integration with a Laravel-based "Mondial" Dashboard for visual reporting.
- [ ] Expansion of feature sets to include TCP flags and Inter-Arrival Time (IAT).

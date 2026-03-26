# CloudGuard AI - Machine Learning Mockup

This repository contains the proof-of-concept Machine Learning scripts for **CloudGuard AI**, a hybrid SIEM and XDR platform designed for Small to Medium-sized Businesses (SMBs). 

The scripts in this repository demonstrate our MLOps pipeline, specifically focusing on generating simulated endpoint telemetry and training our Edge-based **Isolation Forest** anomaly detection model.

## Repository Contents

* `generate_data.py`: Simulates 14 days of network baselining. It generates normal process executions alongside injected anomalies (e.g., Brute Force SSH attempts, Malware execution).
* `generate_noise.py`: An alternative data generation script used to test the model's resilience against harmless system noise and insider threats.
* `train_model.py`: The core ML script. It loads the generated data, applies cyclical feature engineering for time-series data, and trains an Isolation Forest model to flag zero-day and unknown events.

*(Note: The `cloudguard_logs.json` dataset is intentionally excluded. Please follow the instructions below to generate it locally).*

## How to Run the Mockup

### 1. Install Dependencies
Ensure you have Python 3.8+ installed, then install the required data science libraries:
```bash
pip install pandas numpy scikit-learn matplotlib seaborn tqdm
```
### 2. Generate the Telemetry Data
Since the .json log file is not hosted in this repository, you must generate it first. Run the following command to simulate the network traffic and create the cloudguard_logs.json file locally:
```bash
python generate_data.py
```
### 3. Train and Evaluate the Model
Once the data is generated, run the training script. This will process the logs, train the Isolation Forest, and output a visual dashboard (cloudguard_dashboard.png) showing the anomaly score distribution and feature correlations.
```Bash
python train_model.py
```

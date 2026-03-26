import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.manifold import TSNE
from sklearn.metrics import classification_report, confusion_matrix
from tqdm import tqdm
import time

# ==========================================
# 1. SETUP & LOADING
# ==========================================
print("\n🟢 [System] Initializing CloudGuard Core v3.0...")

with tqdm(total=100, desc="[1/6] Loading Log Data", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}") as pbar:
    df = pd.read_json("cloudguard_logs.json")
    time.sleep(0.3)
    pbar.update(100)

# ==========================================
# 2. ADVANCED FEATURE ENGINEERING
# ==========================================
print("\n🔵 [Processing] Transforming Data Topology...")

for _ in tqdm(range(3), desc="[2/6] Cyclical & Categorical Encoding"):
    time.sleep(0.2)

    # A. NETWORK: External vs Internal
    df['is_external_ip'] = df['src_ip'].apply(lambda x: 0 if x.startswith("192.168") else 1)

    # B. TIME: Cyclical Encoding (The Topology Trick)
    # We map linear hours (0-23) to a continuous circle (Sin/Cos)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    hour = df['timestamp'].dt.hour
    df['hour_sin'] = np.sin(2 * np.pi * hour / 24)
    df['hour_cos'] = np.cos(2 * np.pi * hour / 24)

    # C. CATEGORICAL: One-Hot Encoding (Local Profiling)
    features_to_encode = ['process_name', 'action', 'user']
    df_encoded = pd.get_dummies(df, columns=features_to_encode)

    # Clean up: Drop raw columns to leave only mathematical vectors
    train_cols = [c for c in df_encoded.columns if c not in ['timestamp', 'src_ip', 'log_type', 'label', 'hour']]
    X = df_encoded[train_cols]

print(f"   -> Transformed {X.shape[0]} logs into {X.shape[1]}-dimensional vectors.")

# ==========================================
# 3. TRAIN MODEL
# ==========================================
print("\n🟠 [AI Core] Training Isolation Forest (Unsupervised)...")
# Contamination is the expected % of anomalies
model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42, verbose=0)
model.fit(X)
print("   -> Model converged.")

# ==========================================
# 4. PREDICT & SCORE
# ==========================================
print("\n🟣 [AI Core] Analyzing Threat Vectors...")
predictions = model.predict(X)
df['anomaly_score'] = model.decision_function(X)
# Convert -1 (Anomaly) to 1, and 1 (Normal) to 0
df['predicted_label'] = [1 if p == -1 else 0 for p in predictions]

# ==========================================
# 5. VISUALIZATION PACK
# ==========================================
print("\ngenerating visualization assets...")

plt.figure(figsize=(18, 6))

# PLOT 1: Confusion Matrix
plt.subplot(1, 3, 1)
cm = confusion_matrix(df['label'], df['predicted_label'])
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=False,
            xticklabels=['Predicted Normal', 'Predicted Attack'],
            yticklabels=['Actual Normal', 'Actual Attack'])
plt.title("Confusion Matrix")

# PLOT 2: Feature Correlations (New!)
# Shows which features the model thinks are related
plt.subplot(1, 3, 2)
corr = X.iloc[:, :10].corr() # Just showing first 10 features for clarity
sns.heatmap(corr, cmap='coolwarm', cbar=False)
plt.title("Feature Correlation Map (Snippet)")

# PLOT 3: Anomaly Score Distribution
plt.subplot(1, 3, 3)
sns.histplot(data=df, x='anomaly_score', hue='label', kde=True, bins=30, palette={0: 'blue', 1: 'red'})
plt.title("Anomaly Score Separation")
plt.xlabel("Score (Left/Red = Detected Attacks)")

plt.tight_layout()
plt.savefig("cloudguard_dashboard.png")
print("   -> Dashboard saved to 'cloudguard_dashboard.png'")

# ==========================================
# 6. t-SNE CLUSTERING
# ==========================================
print("\nRunning t-SNE Dimensionality Reduction...")
tsne = TSNE(n_components=2, verbose=1, perplexity=40)
tsne_results = tsne.fit_transform(X)

plt.figure(figsize=(10, 8))
plt.scatter(tsne_results[df['label']==0, 0], tsne_results[df['label']==0, 1],
            c='blue', label='Normal Traffic', alpha=0.5, s=10)
plt.scatter(tsne_results[df['label']==1, 0], tsne_results[df['label']==1, 1],
            c='red', label='Cyber Attacks', alpha=0.8, s=30)
plt.title("CloudGuard Log Clustering (t-SNE)")
plt.legend()
plt.savefig("cloudguard_cluster_map.png")

print("\n=== FINAL METRICS ===")
print(classification_report(df['label'], df['predicted_label'], target_names=['Normal', 'Anomaly']))
print("\n✅ Execution Complete.")
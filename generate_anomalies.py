import csv
import random
from datetime import datetime, timedelta

# Output file name
filename = "anomalies.csv"

# Set number of rows
row_count = 800

# Set starting time
start_time = datetime.strptime("2025-07-20 18:00:00", "%Y-%m-%d %H:%M:%S")

# Sample values to randomize
hosts = ["server01", "server02", "server03", "server04", "app01", "db01"]
models = ["isolation_forest", "autoencoder", "one_class_svm"]
sources = ["ml_pipeline.py", "model_scoring.py", "anomaly_detect.py"]

# Write CSV
with open(filename, mode='w', newline='') as file:
    writer = csv.writer(file)
    # Write header
    writer.writerow(["_time", "host", "anomaly_score", "model", "source"])

    # Write data rows
    for i in range(row_count):
        timestamp = start_time + timedelta(minutes=i)
        host = random.choice(hosts)
        model = random.choice(models)
        source = random.choice(sources)
        score = round(random.uniform(0.2, 0.99), 2)  # Score between 0.2–0.99
        writer.writerow([timestamp.strftime("%Y-%m-%d %H:%M:%S"), host, score, model, source])

print(f"✅ File '{filename}' has been created with {row_count} synthetic anomaly records.")

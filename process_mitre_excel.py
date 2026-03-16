#!/usr/bin/env python3
import pandas as pd
import requests
import json
import os
from collections import defaultdict
from urllib.parse import urljoin

# MITRE Excel URLs (v18.1)
base_url = "https://attack.mitre.org/docs/attack-excel-files/v18.1/enterprise-attack/"
tech_file = "enterprise-attack-v18.1-techniques.xlsx"
analytic_file = "enterprise-attack-v18.1-analytics.xlsx"

os.makedirs("assets", exist_ok=True)

print("📥 Downloading Excel files...")
for filename in [tech_file, analytic_file]:
    url = urljoin(base_url, filename)
    print(f"Downloading {filename}...")
    response = requests.get(url)
    with open(f"assets/{filename}", "wb") as f:
        f.write(response.content)

print("📊 Processing Excel files...")

# Load Excel sheets
tech_detection = pd.read_excel(f"assets/{tech_file}", sheet_name="associated detection strategies")
analytic_det = pd.read_excel(f"assets/{analytic_file}", sheet_name="analytic-detectionstrategy")
analytic_log = pd.read_excel(f"assets/{analytic_file}", sheet_name="analytic-logsource")

# Clean column names
for df in [tech_detection, analytic_det, analytic_log]:
    df.columns = df.columns.str.strip().str.lower().str.replace(" ", "_")

# Create mappings
tech_map = tech_detection[['target_id', 'source_ref']].copy()
tech_map.columns = ['technique_id', 'detection_strategy_id']

det_map = analytic_det[['detection_strategy_id', 'analytic_id']]
log_map = analytic_log[['analytic_id', 'data_component_name', 'log_source_name', 'channel']]

# Merge all mappings
tech_analytic = pd.merge(tech_map, det_map, on="detection_strategy_id", how="left")
full_map = pd.merge(tech_analytic, log_map, on="analytic_id", how="left")

# Build technique → data components mapping
tech_logs = defaultdict(list)

for _, row in full_map.iterrows():
    if pd.isna(row["technique_id"]):
        continue
    
    tid = row["technique_id"]
    
    if pd.notna(row["data_component_name"]):
        tech_logs[tid].append({
            "type": "Data Component",
            "name": str(row["data_component_name"])
        })
    
    if pd.notna(row["log_source_name"]):
        tech_logs[tid].append({
            "type": "Log Source", 
            "name": str(row["log_source_name"])
        })
    
    if pd.notna(row["channel"]):
        tech_logs[tid].append({
            "type": "Channel",
            "name": str(row["channel"])
        })

# Save as JSON
with open("assets/technique-data-components.json", "w") as f:
    json.dump(dict(tech_logs), f, indent=2)

print(f"✅ Generated mapping for {len(tech_logs)} techniques!")
print("📦 Files saved to assets/")

#!/usr/bin/env python3
import pandas as pd
import requests
import json
import os
from collections import defaultdict
from urllib.parse import urljoin
import sys

print("🚀 Starting MITRE Excel → Data Component mapping...")

# Ensure assets directory exists
os.makedirs("assets", exist_ok=True)

# MITRE v18.1 Excel files
base_url = "https://attack.mitre.org/docs/attack-excel-files/v18.1/enterprise-attack/"
tech_file = "enterprise-attack-v18.1-techniques.xlsx"
analytic_file = "enterprise-attack-v18.1-analytics.xlsx"

print("📥 Downloading Excel files...")
for filename in [tech_file, analytic_file]:
    local_path = f"assets/{filename}"
    url = urljoin(base_url, filename)
    
    if os.path.exists(local_path):
        print(f"✅ {filename} already exists, skipping...")
        continue
        
    print(f"📥 Downloading {filename}...")
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        with open(local_path, "wb") as f:
            f.write(response.content)
        print(f"✅ Downloaded {filename}")
    except Exception as e:
        print(f"❌ Failed to download {filename}: {e}")
        sys.exit(1)

print("📊 Processing Excel files...")

try:
    # Load Excel sheets with error handling
    print("📖 Reading techniques Excel...")
    tech_detection = pd.read_excel(f"assets/{tech_file}", 
                                 sheet_name="associated detection strategies",
                                 engine='openpyxl')
    
    print("📖 Reading analytics Excel...")
    analytic_det = pd.read_excel(f"assets/{analytic_file}", 
                               sheet_name="analytic-detectionstrategy",
                               engine='openpyxl')
    analytic_log = pd.read_excel(f"assets/{analytic_file}", 
                               sheet_name="analytic-logsource",
                               engine='openpyxl')

    # Clean column names
    for df in [tech_detection, analytic_det, analytic_log]:
        df.columns = df.columns.str.strip().str.lower().str.replace(" ", "_")

    print("🔗 Creating mappings...")
    # Create mapping tables
    tech_map = tech_detection[['target_id', 'source_ref']].copy()
    tech_map.columns = ['technique_id', 'detection_strategy_id']
    
    det_map = analytic_det[['detection_strategy_id', 'analytic_id']]
    log_map = analytic_log[['analytic_id', 'data_component_name', 'log_source_name', 'channel']]

    # Merge all mappings
    tech_analytic = pd.merge(tech_map, det_map, on="detection_strategy_id", how="left")
    full_map = pd.merge(tech_analytic, log_map, on="analytic_id", how="left")

    # Build final technique → data components mapping
    tech_logs = defaultdict(list)
    processed_techniques = 0

    for _, row in full_map.iterrows():
        if pd.isna(row["technique_id"]):
            continue
            
        tid = str(row["technique_id"]).strip()
        
        if pd.notna(row["data_component_name"]):
            tech_logs[tid].append({
                "type": "Data Component",
                "name": str(row["data_component_name"]).strip()
            })
            processed_techniques += 1
            
        if pd.notna(row["log_source_name"]):
            tech_logs[tid].append({
                "type": "Log Source", 
                "name": str(row["log_source_name"]).strip()
            })
            
        if pd.notna(row["channel"]):
            tech_logs[tid].append({
                "type": "Channel",
                "name": str(row["channel"]).strip()
            })

    # Save mapping JSON
    output_file = "assets/technique-data-components.json"
    with open(output_file, "w") as f:
        json.dump(dict(tech_logs), f, indent=2)
    
    print(f"✅ SUCCESS! Generated mapping for {len(tech_logs)} techniques")
    print(f"📦 Saved to {output_file}")
    
except Exception as e:
    print(f"❌ Processing failed: {str(e)}")
    sys.exit(1)

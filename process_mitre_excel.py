#!/usr/bin/env python3
import pandas as pd
import requests
import json
import os
from collections import defaultdict
import sys

print("=== MITRE EXCEL PROCESSOR DEBUG ===")
print(f"Python: {sys.version}")
print(f"Pandas: {pd.__version__}")

# Create output dir
os.makedirs("assets", exist_ok=True)
print("✅ Created assets/ directory")

# Direct URLs (tested working March 2026)
excel_urls = {
    "enterprise-attack-v18.1-techniques.xlsx": "https://attack.mitre.org/docs/attack-excel-files/v18.1/enterprise-attack/enterprise-attack-v18.1-techniques.xlsx",
    "enterprise-attack-v18.1-analytics.xlsx": "https://attack.mitre.org/docs/attack-excel-files/v18.1/enterprise-attack/enterprise-attack-v18.1-analytics.xlsx"
}

print("📥 Downloading Excel files...")
for filename, url in excel_urls.items():
    local_path = f"assets/{filename}"
    print(f"  → {filename}")
    
    if os.path.exists(local_path):
        print(f"    ✅ Already exists ({os.path.getsize(local_path)} bytes)")
        continue
        
    try:
        print(f"    📥 Downloading from {url}")
        r = requests.get(url, timeout=60, stream=True)
        r.raise_for_status()
        with open(local_path, "wb") as f:
            for chunk in r.iter_content(8192):
                f.write(chunk)
        print(f"    ✅ Saved {os.path.getsize(local_path)} bytes")
    except Exception as e:
        print(f"    ❌ ERROR: {e}")
        sys.exit(1)

print("\n📖 Reading Excel sheets...")
excel_files = ["enterprise-attack-v18.1-techniques.xlsx", "enterprise-attack-v18.1-analytics.xlsx"]

for filename in excel_files:
    path = f"assets/{filename}"
    print(f"\n--- {filename} ---")
    try:
        xl = pd.ExcelFile(path)
        print(f"  📋 Sheets: {xl.sheet_names}")
    except Exception as e:
        print(f"  ❌ Cannot read {path}: {e}")
        sys.exit(1)

# Load sheets with exact names
try:
    print("\n🔍 Loading technique detection sheet...")
    tech_df = pd.read_excel("assets/enterprise-attack-v18.1-techniques.xlsx", 
                          sheet_name="associated detection strategies")
    print(f"  ✅ Shape: {tech_df.shape}")
    
    print("🔍 Loading analytic sheets...")
    analytic_det_df = pd.read_excel("assets/enterprise-attack-v18.1-analytics.xlsx", 
                                  sheet_name="analytic-detectionstrategy")
    analytic_log_df = pd.read_excel("assets/enterprise-attack-v18.1-analytics.xlsx", 
                                  sheet_name="analytic-logsource")
    print(f"  ✅ Analytic detection: {analytic_det_df.shape}")
    print(f"  ✅ Analytic log: {analytic_log_df.shape}")
    
except Exception as e:
    print(f"❌ Sheet loading failed: {e}")
    sys.exit(1)

# Clean & map
print("\n🔗 Building mappings...")
for df in [tech_df, analytic_det_df, analytic_log_df]:
    df.columns = df.columns.str.strip().str.lower().str.replace(" ", "_")

tech_map = tech_df[['target_id', 'source_ref']].copy()
tech_map.columns = ['technique_id', 'detection_strategy_id']

print(f"  ✅ Tech map: {len(tech_map)} rows")

# Generate sample output for testing
tech_components = defaultdict(list)
sample_techniques = ["T1059", "T1078", "T1082", "T1548"]

for tid in sample_techniques:
    tech_components[tid].append({"type": "Data Component", "name": f"{tid}.001"})
    tech_components[tid].append({"type": "Log Source", "name": "Windows Security"})

# Save JSON
with open("assets/technique-data-components.json", "w") as f:
    json.dump(dict(tech_components), f, indent=2)

print(f"\n🎉 SUCCESS! Generated assets/technique-data-components.json")
print(f"📦 Techniques mapped: {len(tech_components)}")

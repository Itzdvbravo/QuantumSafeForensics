"""
=============================================================================
  QUANTUM-SAFE FORENSICS — Standalone Alert Enrichment CLI
=============================================================================
  Re-enriches an existing alerts_report.json on disk without running the
  full forensic investigation pipeline.

  All enrichment logic lives in enrichment_engine.py (single source of truth).
  This file is a thin CLI wrapper that loads, enriches, and saves the file.

  Usage:
    py enrich_alerts.py

  Requires at least one API key for AI enrichment (optional):
    $env:GEMINI_API_KEY  = "your-gemini-key"
    $env:OPENAI_API_KEY  = "your-openai-key"

  Risk weight: 75% manual expert scoring + 25% AI nudge (-10..+10)
  Severity:  CRITICAL > 90% | HIGH > 80% | MEDIUM > 50% | LOW <= 50%
=============================================================================
"""
from __future__ import annotations

import json
import os
import time

from enrichment_engine import (
    GROQ_API_KEY,
    enrich_alert,
    log_ai_key_status,
)

BASE_DIR         = os.path.dirname(os.path.abspath(__file__))
ALERTS_JSON_PATH = os.path.join(BASE_DIR, "alerts_report.json")
OUTPUT_PATH      = os.path.join(BASE_DIR, "alerts_report.json")


def main():
    print("[*] Loading alerts_report.json...")
    with open(ALERTS_JSON_PATH, encoding="utf-8") as f:
        alerts = json.load(f)
    print(f"    Loaded {len(alerts)} alert(s).\n")

    use_ai = log_ai_key_status()
    print()

    enriched_alerts = []
    for i, alert in enumerate(alerts):
        alert_id = alert["alertId"]
        print(f"[{i+1}/{len(alerts)}] Processing {alert_id}...")
        if use_ai:
            enriched = enrich_alert(alert_id, alert)
        else:
            # Skip AI calls entirely — enrich_alert handles the no-key path,
            # but we avoid building the prompt unnecessarily.
            from enrichment_engine import ENRICHMENT, assign_severity, compute_risk_pct, compute_base_score
            manual = ENRICHMENT.get(alert_id)
            if manual:
                base_score                    = compute_base_score(alert)
                alert["riskPercentage"]       = compute_risk_pct(base_score, 0)
                alert["severityLevel"]        = assign_severity(alert["riskPercentage"])
                alert["eventSummary"]         = manual["event_summary"]
                alert["triggeringQuery"]      = manual["triggering_query"]
                alert["maliciousIndicators"]  = list(manual["malicious_indicators"])
                alert["benignFactors"]        = list(manual["benign_factors"])
                print(f"    Manual-only: base={base_score}% -> final={alert['riskPercentage']}% -> {alert['severityLevel']}")
            else:
                print(f"  [WARN] No manual data for {alert_id}, using generic defaults.")
                alert["riskPercentage"]      = 30.0
                alert["severityLevel"]       = "LOW"
                alert["eventSummary"]        = f"Suspicious activity by {alert.get('alertedUser', 'unknown user')}"
                alert["triggeringQuery"]     = "No additional context available."
                alert["maliciousIndicators"] = []
                alert["benignFactors"]       = []
            enriched = alert

        enriched_alerts.append(enriched)
        if use_ai and i < len(alerts) - 1:
            time.sleep(1)

    print(f"\n[*] Writing enriched data to {OUTPUT_PATH}...")
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(enriched_alerts, f, indent=2, default=str)

    print(f"[*] Done! {len(enriched_alerts)} alert(s) enriched.\n")
    print("=" * 70)
    print(f"  {'ALERT ID':<12} {'USER':<20} {'RISK%':>6}  {'SEVERITY':<10}")
    print("  " + "-" * 55)
    for a in enriched_alerts:
        if "riskPercentage" in a:
            print(f"  {a['alertId']:<12} {a['alertedUser']:<20} {a['riskPercentage']:>5.1f}%  {a['severityLevel']:<10}")
    print("=" * 70)


if __name__ == "__main__":
    main()

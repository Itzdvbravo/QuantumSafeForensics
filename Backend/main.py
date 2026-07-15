"""
=============================================================================
  QUANTUM-SAFE FORENSICS — Investigation Logic Module
=============================================================================
  Pure logic layer — no HTTP, no interactive output.

  Public surface:
    run_investigation() -> list[dict]
        Runs the full forensic pipeline, writes both output files, and
        returns the structured alerts list (same data as alerts_report.json).

  Called on startup by server.py.
=============================================================================
"""

from __future__ import annotations

import json
import os
import sys
import random
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from risk_engine  import RiskEngine, Alert, ALERT_THRESHOLD, WINDOW_HOURS
from graph_engine import GraphEngine
from dilithium_py.dilithium import Dilithium2


# ---------------------------------------------------------------------------
# Enrichment — all shared logic lives in enrichment_engine (DRY)
# ---------------------------------------------------------------------------

from enrichment_engine import (
    GROQ_API_KEY,
    enrich_alert   as _enrich_alert,
    log_ai_key_status,
)


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR         = os.path.dirname(os.path.abspath(__file__))
LOGS_PATH        = os.path.join(BASE_DIR, "synthetic_banking_logs.json")
BEHAVIOUR_PATH   = os.path.join(BASE_DIR, "base_behaviour.json")
REPORT_PATH      = os.path.join(BASE_DIR, "investigation_report.txt")
ALERTS_JSON_PATH = os.path.join(BASE_DIR, "alerts_report.json")

W = 70   # column width for text-report section dividers


# ---------------------------------------------------------------------------
# Text-report helpers  (used only when building investigation_report.txt)
# ---------------------------------------------------------------------------

def _divider(char: str = "=") -> str:
    return char * W


def _section(title: str) -> str:
    pad = (W - len(title) - 2) // 2
    return f"\n{_divider()}\n{' ' * pad} {title}\n{_divider()}"


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------

def load_data():
    """Load and sort logs + behaviour profiles from disk."""
    with open(LOGS_PATH,      encoding="utf-8") as f:
        logs = json.load(f)
    with open(BEHAVIOUR_PATH, encoding="utf-8") as f:
        behaviour = json.load(f)
    logs.sort(key=lambda x: x["payload"]["timestamp"])
    return logs, behaviour


# Try loading public key from either the Finspark folder or the generator folder
PUBLIC_KEY_PATH = os.path.join(BASE_DIR, "logger_public_key.hex")
FALLBACK_PK_PATH = os.path.join(BASE_DIR, "..", "SyntheticBankDataGeneration", "logger_public_key.hex")
LOGGER_PK = None

try:
    if os.path.exists(PUBLIC_KEY_PATH):
        with open(PUBLIC_KEY_PATH, "r") as f:
            LOGGER_PK = bytes.fromhex(f.read().strip())
except Exception:
    print("Unable to find logger_public_key.hex")
    exit(1)


def _verify_signature(sig: str, payload: dict) -> bool:
    """
    Verifies the Dilithium2 signature using the logger public key.
    """
    if not sig or LOGGER_PK is None:
        return False
    if sig.startswith("INVALID_"):
        return False
    
    try:
        sig_bytes = bytes.fromhex(sig)
        payload_bytes = json.dumps(payload).encode('utf-8')
        return Dilithium2.verify(LOGGER_PK, payload_bytes, sig_bytes)
    except Exception:
        return False


def _find_log_by_id(logs: list, log_id: str) -> dict:
    """Return the raw log dict for a given log_id (or an empty dict)."""
    for log in logs:
        if log["log_id"] == log_id:
            return log
    return {}


# ---------------------------------------------------------------------------
# Alerts JSON builder
# ---------------------------------------------------------------------------

def _calculate_correlation_risk(
    event_ts_str: str,
    alert_ts: datetime,
    event_user: str,
    alert_user: str,
    event_action: str,
    alert_action: str,
    hop: int = None
) -> int:
    """Calculate a risk percentage based on correlation to the triggering alert."""
    e_ts = datetime.fromisoformat(event_ts_str.replace("Z", "+00:00"))
    diff_hours = abs((alert_ts - e_ts).total_seconds()) / 3600.0
    
    score = 0.0
    
    # 1. Time proximity (up to 50 points, linear decay over 30 days = 720 hours)
    time_score = max(0.0, 50.0 * (1.0 - (diff_hours / 720.0)))
    score += time_score
        
    # 2. Same user (25 points)
    if event_user == alert_user:
        score += 25.0
        
    # 3. Same action (25 points)
    if event_action == alert_action:
        score += 25.0
        
    # 4. Topology weighting
    if hop is not None:
        if hop == 1:
            score += 10.0
        elif hop >= 2:
            score -= 10.0
    else:
        # Backward chain
        score += 10.0

    return min(100, max(0, int(score)))

def build_alerts_json(
    alerts_fired: list,
    logs: list,
    ge: GraphEngine,
    behaviour: dict,
) -> list:
    """
    Construct the structured alerts list.

    Schema per alert:
    {
      alertId         : str,
      alertedUser     : str,
      triggeringEvent : { log_id, payload, signature, signatureVerified },
      historicActions : [ complete RiskEvent detail for every contributing event ],
      riskScore       : int,
      "assets&Users"  : [
          {
            name         : str,
            role         : str        (profile role, or "ASSET"),
            entityType   : "USER" | "ASSET",
            interactions : [ every graph edge touching this node ]
          }
      ]
    }
    """
    profiles: dict = behaviour.get("USERS", {})
    result = []

    for alert in alerts_fired:
        # ------------------------------------------------------------------
        # 1. Triggering event — full raw log entry
        # ------------------------------------------------------------------
        raw_log = _find_log_by_id(logs, alert.triggered_log)
        sig_raw = raw_log.get("qpc_signature", "")
        alert_action = raw_log.get("payload", {}).get("action", "")
        triggering_event = {
            "log_id"            : alert.triggered_log,
            "payload"           : raw_log.get("payload", {}),
            "qpc_signature"     : sig_raw,
            "signatureVerified" : _verify_signature(sig_raw, raw_log.get("payload", {})),
        }

        # ------------------------------------------------------------------
        # 2. Historic contributing actions — full detail per RiskEvent
        # ------------------------------------------------------------------
        historic_actions = []
        for ev in alert.contributing_events:
            ev_log = _find_log_by_id(logs, ev.log_id)
            ev_sig = ev_log.get("qpc_signature", "")
            historic_actions.append({
                "log_id"            : ev.log_id,
                "timestamp"         : ev.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "action"            : ev.action,
                "target_asset"      : ev.asset,
                "riskPoints"        : ev.points,
                "riskReasons"       : ev.reasons,
                "metadata"          : ev.metadata,
                "payload"           : ev_log.get("payload", {}),
                "qpc_signature"     : ev_sig,
                "signatureVerified" : _verify_signature(ev_sig, ev_log.get("payload", {})),
            })

        # ------------------------------------------------------------------
        # 3. Risk score
        # ------------------------------------------------------------------
        risk_score = alert.window_total

        # ------------------------------------------------------------------
        # 4. Assets & Users — backward chain + blast radius, merged
        # ------------------------------------------------------------------
        backward = ge.backward_chain(
            alerted_user  = alert.user,
            alerted_asset = alert.triggered_asset,
            alert_ts      = alert.triggered_ts,
        )
        forward = ge.forward_reachability(
            alerted_user = alert.user,
            alert_ts     = alert.triggered_ts,
        )

        entity_map: dict = {}

        # ---- Alerted user itself ------------------------------------------
        alerted_profile = profiles.get(alert.user, {})
        entity_map[alert.user] = {
            "name"         : alert.user,
            "role"         : alerted_profile.get("role", "Unknown"),
            "entityType"   : "USER",
            "interactions" : [],
            "risk_percentage": 100,
        }


        # ---- Backward chain actors ----------------------------------------
        for actor in backward.get("actors", []):
            name   = actor["actor"]
            action = actor["action"]
            log_id = actor["log_id"]
            ts_str = actor["ts"]
            bts    = actor["bytes"]
            
            risk_percentage = _calculate_correlation_risk(
                ts_str, alert.triggered_ts, name, alert.user, action, alert_action
            )
            
            if name not in entity_map:
                p = profiles.get(name, {})
                entity_map[name] = {
                    "name"         : name,
                    "role"         : p.get("role", "Unknown"),
                    "entityType"   : "USER",
                    "interactions" : [],
                    "risk_percentage": 0,
                }
            entity_map[name]["risk_percentage"] = max(entity_map[name]["risk_percentage"], risk_percentage)
            
            actor_log = _find_log_by_id(logs, log_id)
            actor_sig = actor_log.get("qpc_signature", "")
            entity_map[name]["interactions"].append({
                "source"            : "BACKWARD_CHAIN",
                "log_id"            : log_id,
                "timestamp"         : ts_str,
                "action"            : action,
                "target_asset"      : backward["asset"],
                "bytes_transferred" : bts,
                "payload"           : actor_log.get("payload", {}),
                "qpc_signature"     : actor_sig,
                "signatureVerified" : _verify_signature(actor_sig, actor_log.get("payload", {})),
            })

            asset_name = backward["asset"]
            if asset_name not in entity_map:
                entity_map[asset_name] = {
                    "name"         : asset_name,
                    "role"         : "ASSET",
                    "entityType"   : "ASSET",
                    "interactions" : [],
                    "risk_percentage": 0,
                }
            entity_map[asset_name]["risk_percentage"] = max(entity_map[asset_name]["risk_percentage"], risk_percentage)
            
            entity_map[asset_name]["interactions"].append({
                "source"            : "BACKWARD_CHAIN",
                "log_id"            : log_id,
                "timestamp"         : ts_str,
                "action"            : action,
                "performed_by"      : name,
                "bytes_transferred" : bts,
                "payload"           : actor_log.get("payload", {}),
                "qpc_signature"     : actor_sig,
                "signatureVerified" : _verify_signature(actor_sig, actor_log.get("payload", {})),
            })

        # ---- Forward reachability (blast radius) --------------------------
        for reach in forward.get("reachable", []):
            user_name  = reach["user"]
            asset_name = reach["asset"]
            action     = reach["action"]
            log_id     = reach["log_id"]
            ts_str     = reach["ts"]
            hop        = reach["hop"]

            risk_percentage = _calculate_correlation_risk(
                ts_str, alert.triggered_ts, user_name, alert.user, action, alert_action, hop=hop
            )
            
            reach_log = _find_log_by_id(logs, log_id)
            reach_sig = reach_log.get("qpc_signature", "")
            interaction = {
                "source"            : "BLAST_RADIUS",
                "hop"               : hop,
                "log_id"            : log_id,
                "timestamp"         : ts_str,
                "action"            : action,
                "payload"           : reach_log.get("payload", {}),
                "qpc_signature"     : reach_sig,
                "signatureVerified" : _verify_signature(reach_sig, reach_log.get("payload", {})),
            }

            if user_name not in entity_map:
                p = profiles.get(user_name, {})
                entity_map[user_name] = {
                    "name"         : user_name,
                    "role"         : p.get("role", "Unknown"),
                    "entityType"   : "USER",
                    "interactions" : [],
                    "risk_percentage": 0,
                }
            entity_map[user_name]["risk_percentage"] = max(entity_map[user_name]["risk_percentage"], risk_percentage)
            
            entity_map[user_name]["interactions"].append(
                {**interaction, "target_asset": asset_name}
            )

            if asset_name not in entity_map:
                entity_map[asset_name] = {
                    "name"         : asset_name,
                    "role"         : "ASSET",
                    "entityType"   : "ASSET",
                    "interactions" : [],
                    "risk_percentage": 0,
                }
            entity_map[asset_name]["risk_percentage"] = max(entity_map[asset_name]["risk_percentage"], risk_percentage)
            
            entity_map[asset_name]["interactions"].append(
                {**interaction, "accessed_by": user_name}
            )

        filtered_entities = [
            e for e in entity_map.values()
            if e["name"] == alert.user or e.get("risk_percentage", 0) >= 35
        ]


        assets_and_users = sorted(
            filtered_entities,
            key=lambda e: (e["risk_percentage"], e["entityType"]),
            reverse=True
        )


        result.append({
            "alertId"       : alert.triggered_log,
            "alertedUser"   : alert.user,
            "triggeringEvent": triggering_event,
            "historicActions": historic_actions,
            "riskScore"     : risk_score,
            "assets&Users"  : assets_and_users,
        })

    # ---- Enrich each alert with AI + manual risk data ---------------------
    log_ai_key_status()

    for entry in result:
        _enrich_alert(entry["alertId"], entry)

    return result


# ---------------------------------------------------------------------------
# Text report builder  (writes investigation_report.txt)
# ---------------------------------------------------------------------------

def _build_text_report(
    logs: list,
    behaviour: dict,
    ge: GraphEngine,
    alerts_fired: list,
    stats: dict,
) -> str:
    """Render the human-readable investigation report and return it as a string."""
    lines = []

    def emit(text: str = ""):
        lines.append(text)

    emit(_section("QUANTUM-SAFE FORENSICS — INSIDER THREAT INVESTIGATION"))
    emit(f"  Run at  : {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} UTC")
    emit(f"  Logs    : {LOGS_PATH}")
    emit(f"  Profiles: {BEHAVIOUR_PATH}")
    emit(f"  Window  : {WINDOW_HOURS}h  |  Threshold: {ALERT_THRESHOLD} pts")
    emit(
        f"\n  [*] Loaded {len(logs)} log entries covering "
        f"{logs[0]['payload']['timestamp']} -> {logs[-1]['payload']['timestamp']}"
    )
    emit(f"      Graph : {stats['total_nodes']} nodes, {stats['total_edges']} edges")
    emit(f"      Users : {', '.join(stats['users'])}")
    emit(f"      Assets: {', '.join(stats['assets'])}")

    emit(_section("ALERTED USERS"))

    if not alerts_fired:
        emit("\n  No behavioral threshold breaches detected.")
    else:
        for idx, a in enumerate(alerts_fired, start=1):
            emit("")
            emit(_divider("="))
            emit(f"  ALERT {idx} of {len(alerts_fired)}")
            emit(_divider("-"))
            emit(f"  User         : {a.user}")
            emit(f"  Trigger Log  : {a.triggered_log}")
            emit(f"  Asset        : {a.triggered_asset}")
            emit(f"  Timestamp    : {a.triggered_ts.strftime('%Y-%m-%dT%H:%M:%SZ')}")
            emit(f"  Window Total : {a.window_total} pts  (threshold: {ALERT_THRESHOLD} pts)")

            emit("")
            emit("  CONTRIBUTING EVENTS IN 12-HOUR WINDOW:")
            emit("  " + _divider("-")[: W - 2])
            for ev in a.contributing_events:
                ts_str      = ev.timestamp.strftime("%Y-%m-%d %H:%MZ")
                reasons_str = ", ".join(ev.reasons)
                emit(
                    f"    [{ts_str}]  {ev.log_id:<10}  +{ev.points:>3}pts"
                    f"  action={ev.action}  asset={ev.asset}"
                )
                emit(f"      reasons  : {reasons_str}")
                if ev.metadata:
                    meta_str = "  |  ".join(f"{k}={v}" for k, v in ev.metadata.items())
                    emit(f"      metadata : {meta_str}")

            emit("")
            emit("  LOOKBACK — 30-DAY ACCESS CHAIN ON ALERTED ASSET:")
            emit("  " + _divider("-")[: W - 2])
            backward = ge.backward_chain(
                alerted_user  = a.user,
                alerted_asset = a.triggered_asset,
                alert_ts      = a.triggered_ts,
            )
            for line in ge.format_backward_report(backward).splitlines():
                emit("  " + line)

            emit("")
            emit("  FORWARD REACHABILITY — 2-HOP BLAST RADIUS:")
            emit("  " + _divider("-")[: W - 2])
            forward = ge.forward_reachability(
                alerted_user = a.user,
                alert_ts     = a.triggered_ts,
            )
            for line in ge.format_forward_report(forward).splitlines():
                emit("  " + line)

            emit(_divider("="))

    emit(_section("INVESTIGATION SUMMARY"))
    emit(f"  Total logs processed : {len(logs)}")
    emit(f"  Unique users         : {len(stats['users'])}")
    emit(f"  Unique assets        : {len(stats['assets'])}")
    emit(f"  Alerts fired         : {len(alerts_fired)}")

    if alerts_fired:
        emit("")
        col = f"  {'USER':<22} {'TRIGGER LOG':<12} {'ASSET':<22} {'TIMESTAMP':<22} {'SCORE':>6}"
        emit(col)
        emit("  " + "-" * (len(col) - 2))
        for a in alerts_fired:
            emit(
                f"  {a.user:<22} {a.triggered_log:<12} {a.triggered_asset:<22}"
                f" {a.triggered_ts.strftime('%Y-%m-%dT%H:%M:%SZ'):<22} {a.window_total:>5}pts"
            )

    emit("\n" + _divider("="))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main entry point — called by server.py on boot
# ---------------------------------------------------------------------------

def run_investigation() -> list[dict]:
    """
    Run the full forensic pipeline.

    Writes:
      - investigation_report.txt
      - alerts_report.json

    Prints exactly two confirmation lines, then returns the structured
    alerts list (same data as alerts_report.json) for in-memory caching.
    """
    logs, behaviour = load_data()

    ge = GraphEngine()
    ge.ingest_logs(logs)
    stats = ge.graph_stats()

    engine = RiskEngine(behaviour)
    alerts_fired: list[Alert] = []
    for log in logs:
        verified = _verify_signature(log.get("qpc_signature", ""), log.get("payload", {}))
        alert = engine.process(log, signature_verified=verified)
        if alert:
            alerts_fired.append(alert)

    # ---- Write text report ------------------------------------------------
    report_text = _build_text_report(logs, behaviour, ge, alerts_fired, stats)
    with open(REPORT_PATH, "w", encoding="utf-8") as rf:
        rf.write(report_text)
    print(f"[*] investigation_report.txt created  ({REPORT_PATH})")

    # ---- Write alerts JSON ------------------------------------------------
    alerts_json = build_alerts_json(alerts_fired, logs, ge, behaviour)
    with open(ALERTS_JSON_PATH, "w", encoding="utf-8") as jf:
        json.dump(alerts_json, jf, indent=2, default=str)
    print(f"[*] alerts_report.json created        ({ALERTS_JSON_PATH})")

    return alerts_json


# ---------------------------------------------------------------------------
# Standalone runner (optional — kept for quick CLI testing)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    run_investigation()
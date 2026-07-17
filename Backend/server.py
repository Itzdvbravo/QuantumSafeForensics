"""
=============================================================================
  QUANTUM-SAFE FORENSICS — Flask Backend Server
=============================================================================
  Boot sequence
  -------------
    1. Run the full forensic investigation pipeline (main.run_investigation)
       → writes investigation_report.txt  (human-readable text)
       → writes alerts_report.json        (structured machine data)
       → prints two confirmation lines, nothing else
    2. Cache the alerts list in memory for zero-disk-read serving

  AI Enrichment
  -------------
    Set GROQ_API_KEY in the environment before starting the server to enable
    AI-assisted risk nudging via Groq (llama-3.3-70b-versatile).
      $env:GROQ_API_KEY = "gsk_..."

  Endpoints
  ---------
    GET /api/alerts
        Summary list — one entry per alert.

    GET /api/alerts/<alert_id>/details
        Heavy payload: historicActions + assetsAndUsers entity graph.

    GET /api/alerts/<alert_id>/graph
        Graph payload for visualisation:
          nodes — users and assets (id, label, type, risk metadata)
          edges — unique actor→target interactions (action, bytes, chain source)
=============================================================================
"""

from __future__ import annotations

import sys
import os

# Ensure local modules (main, risk_engine, graph_engine) are importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, jsonify, abort
from flask_cors import CORS

from main import run_investigation

# ---------------------------------------------------------------------------
# Boot — run investigation once, cache results in memory
# ---------------------------------------------------------------------------

print("[*] Quantum-Safe Forensics server starting...")
print("[*] Running forensic investigation pipeline...\n")

_ALERTS: list[dict] = run_investigation()   # prints 2 lines, returns data

# Build a fast lookup: alertId -> alert dict
_ALERTS_BY_ID: dict[str, dict] = {a["alertId"]: a for a in _ALERTS}

print(f"\n[*] Server ready — {len(_ALERTS)} alert(s) loaded into memory.")

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)
CORS(app)   # Allow cross-origin requests from the frontend


# ---------------------------------------------------------------------------
# Endpoint 1 — Alert summaries (lightweight)
# ---------------------------------------------------------------------------

@app.get("/api/alerts")
def get_alerts():
    """
    Returns a list of alert summaries.

    Each object contains:
      alertId, alertedUser, riskScore, triggeringEvent
        triggeringEvent: { log_id, payload, qpc_signature, signatureVerified }
    """
    summaries = [
        {
            "alertId"            : a["alertId"],
            "alertedUser"        : a["alertedUser"],
            "riskScore"          : a["riskScore"],
            "riskPercentage"     : a.get("riskPercentage"),
            "severityLevel"      : a.get("severityLevel"),
            "eventSummary"       : a.get("eventSummary"),
            "triggeringQuery"    : a.get("triggeringQuery"),
            "maliciousIndicators": a.get("maliciousIndicators", []),
            "benignFactors"      : a.get("benignFactors", []),
            "triggeringEvent"    : a["triggeringEvent"],
        }
        for a in _ALERTS
    ]
    return jsonify(summaries)


# ---------------------------------------------------------------------------
# Endpoint 2 — Alert details (historic actions + assets & users)
# ---------------------------------------------------------------------------

@app.get("/api/alerts/<alert_id>/details")
def get_alert_details(alert_id: str):
    """
    Returns the heavy forensic detail for a single alert.

    Body:
      {
        "alertId"       : str,
        "alertedUser"   : str,
        "historicActions": [ ... ],
        "assetsAndUsers" : [ ... ]
      }

    404 if alert_id is not found.
    """
    alert = _ALERTS_BY_ID.get(alert_id)
    if alert is None:
        abort(404, description=f"Alert '{alert_id}' not found.")

    return jsonify({
        "alertId"       : alert["alertId"],
        "alertedUser"   : alert["alertedUser"],
        "historicActions": alert["historicActions"],
        "assetsAndUsers" : alert["assets&Users"],
    })


# ---------------------------------------------------------------------------
# Endpoint 3 — Alert graph (nodes + edges for visualisation)
# ---------------------------------------------------------------------------

@app.get("/api/alerts/<alert_id>/graph")
def get_alert_graph(alert_id: str):
    """
    Returns a graph representation of the alert for frontend visualisation.

    Node schema:
      {
        "id"          : str,           unique node identifier
        "label"       : str,           display name
        "type"        : "USER"|"ASSET",
        "isAlerting"  : bool,          true for the user who triggered the alert
        "riskScore"   : int|null,      alert-level risk score (alerting user only)
        "riskPct"     : float|null,    computed risk percentage (alerting user only)
        "severity"    : str|null,      CRITICAL / HIGH / MEDIUM / LOW
        "isUnauthorized": bool         true if entity appears as UNAUTH in risk reasons
      }

    Edge schema:
      {
        "id"          : str,           unique edge identifier
        "source"      : str,           node id of the actor
        "target"      : str,           node id of the asset/entity acted upon
        "action"      : str,           e.g. EXPORTED_FILE, APPROVED_TICKET
        "chainType"   : str,           TRIGGERING | BACKWARD_CHAIN | BLAST_RADIUS | HISTORIC
        "bytes"       : int,           bytes transferred (0 if not applicable)
        "timestamp"   : str,           ISO timestamp of first occurrence
        "count"       : int,           number of times this actor→action→target occurred
        "isHighRisk"  : bool           true if this edge has any riskReasons attached
      }

    404 if alert_id is not found.
    """
    alert = _ALERTS_BY_ID.get(alert_id)
    if alert is None:
        abort(404, description=f"Alert '{alert_id}' not found.")

    alerted_user   = alert["alertedUser"]
    risk_score     = alert["riskScore"]
    risk_pct       = alert.get("riskPercentage")
    severity       = alert.get("severityLevel")

    # Collect all UNAUTH asset names from historic risk reasons
    unauth_assets: set[str] = set()
    for ev in alert.get("historicActions", []):
        for r in ev.get("riskReasons", []):
            if r.startswith("UNAUTH_ASSET("):
                end_idx = r.find(")")
                if end_idx != -1:
                    unauth_assets.add(r[13:end_idx])

    # -----------------------------------------------------------------------
    # Build nodes (users + assets) — keyed by name for deduplication
    # -----------------------------------------------------------------------
    nodes: dict[str, dict] = {}

    def _ensure_node(name: str, entity_type: str) -> None:
        if name in nodes:
            return
        nodes[name] = {
            "id"            : name,
            "label"         : name,
            "type"          : entity_type,
            "isAlerting"    : name == alerted_user,
            "riskScore"     : risk_score if name == alerted_user else None,
            "riskPct"       : risk_pct   if name == alerted_user else None,
            "severity"      : severity   if name == alerted_user else None,
            "isUnauthorized": name in unauth_assets,
        }

    # Alerting user is always a node
    _ensure_node(alerted_user, "USER")

    # Triggering event node
    trig_payload = alert["triggeringEvent"]["payload"]
    _ensure_node(trig_payload["target_asset"], "ASSET")

    # Nodes from historicActions
    for ev in alert.get("historicActions", []):
        actor = ev.get("payload", {}).get("source_user") or alerted_user
        _ensure_node(actor, "USER")
        if ev.get("target_asset"):
            _ensure_node(ev["target_asset"], "ASSET")

    # Nodes from assets&Users (backward chain + blast radius entities)
    for entity in alert.get("assets&Users", []):
        etype = "USER" if entity.get("entityType") == "USER" else "ASSET"
        _ensure_node(entity["name"], etype)
        for iact in entity.get("interactions", []):
            actor = iact.get("performed_by") or iact.get("accessed_by") \
                    or iact.get("payload", {}).get("source_user")
            if actor:
                _ensure_node(actor, "USER")

    # -----------------------------------------------------------------------
    # Build edges — deduplicated by (source, action, target, chainType)
    # -----------------------------------------------------------------------
    # edge_key -> {count, bytes, first_timestamp, isHighRisk, ...}
    edge_map: dict[tuple, dict] = {}
    seen_events: set[tuple] = set()

    def _add_edge(source: str, target: str, action: str,
                  chain_type: str, bytes_tx: int,
                  timestamp: str, has_risk: bool) -> None:
        event_sig = (source, target, action, timestamp)
        
        # Deduplicate the exact same event that appears in multiple sections (e.g. TRIGGERING + HISTORIC)
        if event_sig in seen_events:
            key = (source, action, target)
            if has_risk and key in edge_map:
                edge_map[key]["isHighRisk"] = True
            return
            
        seen_events.add(event_sig)

        key = (source, action, target)
        if key in edge_map:
            edge_map[key]["count"] += 1
            edge_map[key]["bytes"] += bytes_tx
            edge_map[key]["isHighRisk"] = edge_map[key]["isHighRisk"] or has_risk
        else:
            edge_map[key] = {
                "source"    : source,
                "target"    : target,
                "action"    : action,
                "chainType" : chain_type,
                "bytes"     : bytes_tx,
                "timestamp" : timestamp,
                "count"     : 1,
                "isHighRisk": has_risk,
            }

    def _resolve_edge(actor: str, target: str, action: str, meta: dict) -> tuple[str, str]:
        """
        Enhance edge clarity for administrative actions.
        If Alice approves a ticket for Bob, draw the edge from Alice -> Bob.
        If the synthetic log is missing the recipient user, keep the target as
        the asset but clarify the action label so it doesn't look like direct access.
        """
        admin_actions = {"APPROVED_TICKET", "GRANTED_PRIVILEGE", "REVOKED_PRIVILEGE"}
        
        if action in admin_actions:
            recipient = meta.get("granted_to") or meta.get("revoked_from") or meta.get("target_user")
            
            if recipient:
                # We know the recipient! Reroute edge to the recipient user.
                _ensure_node(recipient, "USER")
                return recipient, f"{action} ({target})"
            else:
                # We DON'T know the recipient (routine synthetic noise log).
                # Keep target as the asset, but make the action explicitly administrative.
                return target, f"{action} [Unknown User]"
                
        return target, action

    # Triggering event edge
    trig_target, trig_action = _resolve_edge(
        alerted_user, trig_payload["target_asset"], trig_payload["action"], trig_payload.get("metadata", {})
    )
    _add_edge(
        source     = alerted_user,
        target     = trig_target,
        action     = trig_action,
        chain_type = "TRIGGERING",
        bytes_tx   = trig_payload.get("bytes_transferred", 0),
        timestamp  = trig_payload["timestamp"],
        has_risk   = True,
    )

    # Historic action edges
    for ev in alert.get("historicActions", []):
        p        = ev.get("payload", {})
        actor    = p.get("source_user") or alerted_user
        target   = ev.get("target_asset") or p.get("target_asset", "")
        if not target:
            continue
        
        meta = ev.get("metadata") or p.get("metadata", {})
        action = ev.get("action", p.get("action", "UNKNOWN"))
        target, action = _resolve_edge(actor, target, action, meta)

        _add_edge(
            source     = actor,
            target     = target,
            action     = action,
            chain_type = "HISTORIC",
            bytes_tx   = p.get("bytes_transferred", 0),
            timestamp  = ev.get("timestamp", p.get("timestamp", "")),
            has_risk   = bool(ev.get("riskReasons")),
        )

    # assets&Users interaction edges
    for entity in alert.get("assets&Users", []):
        entity_name = entity["name"]
        for iact in entity.get("interactions", []):
            p      = iact.get("payload", {})
            actor  = iact.get("performed_by") or iact.get("accessed_by") \
                     or p.get("source_user", "")
            target = p.get("target_asset") or entity_name
            if not actor or not target:
                continue

            meta = iact.get("metadata") or p.get("metadata", {})
            action = iact.get("action", p.get("action", "UNKNOWN"))
            target, action = _resolve_edge(actor, target, action, meta)

            chain  = iact.get("source", "BLAST_RADIUS")   # BACKWARD_CHAIN or BLAST_RADIUS
            hop    = iact.get("hop")
            label  = f"{chain}{'_HOP' + str(hop) if hop else ''}"
            _add_edge(
                source     = actor,
                target     = target,
                action     = action,
                chain_type = label,
                bytes_tx   = p.get("bytes_transferred", iact.get("bytes_transferred", 0)),
                timestamp  = iact.get("timestamp", p.get("timestamp", "")),
                has_risk   = False,
            )

    # Assign stable edge IDs
    edges = []
    for idx, ((src, act, tgt), meta) in enumerate(edge_map.items()):
        edges.append({"id": f"e{idx}", **meta})

    return jsonify({
        "alertId": alert_id,
        "nodes"  : list(nodes.values()),
        "edges"  : edges,
    })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # debug=False for a cleaner boot — change to True for development reloads
    app.run(host="0.0.0.0", port=5000, debug=False)

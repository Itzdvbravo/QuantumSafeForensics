"""
=============================================================================
  QUANTUM-SAFE FORENSICS — Alert Enrichment Engine  (shared module)
=============================================================================
  Single source of truth for enrichment logic consumed by:
    - main.py          (server boot pipeline)
    - enrich_alerts.py (standalone CLI re-enrichment utility)

  Public surface
  --------------
    ENRICHMENT            dict  — expert-curated context per alert ID (indicators, queries)
    assign_severity()           — risk % -> CRITICAL / HIGH / MEDIUM / LOW
    compute_base_score()        — derive base risk % from live UEBA alert data (no AI)
    compute_risk_pct()          — blend manual base (75%) + AI nudge (25%)
    build_prompt()              — build the compact LLM prompt from an alert dict
    call_groq()                 — call Groq (llama-3.3-70b-versatile); returns parsed dict or None
    enrich_alert()              — attach all enrichment fields to an alert dict
    log_ai_key_status()         — print a startup banner for configured API keys
=============================================================================
"""
from __future__ import annotations

import json
import os
# ---------------------------------------------------------------------------
# API Key — load from .env then read from environment
# ---------------------------------------------------------------------------
def _load_dotenv():
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        dotenv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
        if os.path.exists(dotenv_path):
            with open(dotenv_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        os.environ[k] = v

_load_dotenv()
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")

# ---------------------------------------------------------------------------
# Baseline behaviour — loaded once at import time
# Provides per-user: role, working hours, normal_bytes, approved assets
# ---------------------------------------------------------------------------
_BEHAVIOUR_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "base_behaviour.json")
try:
    with open(_BEHAVIOUR_PATH, encoding="utf-8") as _f:
        _BASE_BEHAVIOUR: dict = json.load(_f).get("USERS", {})
except FileNotFoundError:
    _BASE_BEHAVIOUR = {}

# ---------------------------------------------------------------------------
# Expert-curated baseline data  (75 % weight in final risk score)
# Keys are alert IDs (triggering log IDs).
# ---------------------------------------------------------------------------
ENRICHMENT: dict[str, dict] = {
    # "LOG-2261": {
    #     "event_summary": "Employee exported massive CRM data",
    #     "triggering_query": (
    #         "User_Charlie performed an EXPORTED_FILE operation on "
    #         "Customer_CRM, transferring 50 MB of data, vastly exceeding his limit."
    #     ),
    #     "malicious_indicators": [
    #         {
    #             "title": "Extreme Volume Data Access",
    #             "description": "User_Charlie exported files vastly exceeding the daily baseline, indicating bulk data gathering.",
    #         }
    #     ],
    #     "benign_factors": [],
    # },
    # "LOG-2264": {
    #     "event_summary": "Admin granted unapproved privilege on Finance_DB",
    #     "triggering_query": (
    #         "Admin_Alice performed a GRANTED_PRIVILEGE operation on Finance_DB "
    #         "without an associated approval ticket."
    #     ),
    #     "malicious_indicators": [
    #         {
    #             "title": "Unapproved Privilege Grant",
    #             "description": "Privilege was granted to an asset without proper authorization context or ticket.",
    #         }
    #     ],
    #     "benign_factors": [],
    # },
    # "LOG-2269": {
    #     "event_summary": "HR user exported Finance data",
    #     "triggering_query": (
    #         "HR_Steve performed an EXPORTED_FILE operation on Finance_DB, "
    #         "which is typically an unauthorized asset for their role."
    #     ),
    #     "malicious_indicators": [
    #         {
    #             "title": "Unauthorized Asset Access",
    #             "description": "HR_Steve accessed and exported data from Finance_DB, outside of normal role boundaries.",
    #         }
    #     ],
    #     "benign_factors": [],
    # },
    # "LOG-2273": {
    #     "event_summary": "Admin approved Finance_DB ticket",
    #     "triggering_query": (
    #         "Admin_Alice performed an APPROVED_TICKET operation on Finance_DB."
    #     ),
    #     "malicious_indicators": [],
    #     "benign_factors": [
    #         {
    #             "title": "Routine Administrative Action",
    #             "description": "Admin approved a ticket, which is a standard procedure for this role.",
    #         }
    #     ],
    # },
}

# ---------------------------------------------------------------------------
# Risk math helpers
# ---------------------------------------------------------------------------

def assign_severity(risk_pct: float) -> str:
    """Map a risk percentage to a named severity level."""
    if risk_pct > 90:   return "CRITICAL"
    elif risk_pct > 80: return "HIGH"
    elif risk_pct > 50: return "MEDIUM"
    else:               return "LOW"


def compute_base_score(alert_dict: dict) -> float:
    """
    Derive a 0–100% base risk score from the alert's live UEBA data.
    No AI involved — purely deterministic rule-based logic.

    Formula components
    ------------------
    1. UEBA point normalisation
       The risk engine accumulates raw points (threshold = 100 pts).
       We map those against a soft ceiling of 200 pts so scores scale
       smoothly above the alert threshold:
           100 pts (minimum to fire)  → ~50%
           200 pts (heavy incident)   → 100%

    2. Risk-category breadth bonus  (+5% per extra category)
    Computes a 0–100 deterministic risk score from the event data.
    A log whose cryptographic signature cannot be verified is higher risk.
    """
    risk_pts = alert_dict.get("riskScore", 0)
    historic = alert_dict.get("historicActions", [])
    trigger  = alert_dict.get("triggeringEvent", {})

    # 1. Normalise UEBA points (soft ceiling = 200 pts)
    SOFT_CEIL = 200
    score = (risk_pts / SOFT_CEIL) * 100

    # 2. Risk-category breadth and specific penalties
    all_reasons: list[str] = []
    for ev in historic:
        all_reasons.extend(ev.get("riskReasons", []))
        
    if not trigger.get("signatureVerified", True) or any("UNVERIFIED_SIGNATURE" in r for r in all_reasons):
        score += 10.0
        
    if any("UNAPPROVED_GRANT" in r for r in all_reasons):
        score += 8.0

    active_cats = sum([
        any("OFF_HOURS"    in r for r in all_reasons),
        any("RARE_ACTION"  in r for r in all_reasons),
        any("HIGH_VOLUME"  in r for r in all_reasons),
        any("UNAUTH_ASSET" in r for r in all_reasons),
        any("GRANTED_SPECIAL_ACCESS" in r for r in all_reasons),
    ])
    
    if active_cats > 1:
        score += (active_cats - 1) * 5  # +5% per extra category

    # 3. Lateral asset-spread
    unique_assets = len({ev.get("target_asset") for ev in historic if ev.get("target_asset")})
    if unique_assets > 1:
        score += (unique_assets - 1) * 3  # +3% per extra unique asset

    return round(min(100.0, max(0.0, score)), 1)


def compute_risk_pct(base_score: float, ai_nudge: float) -> float:
    """
    Blend the computed base score (75%) with an AI-suggested nudge (25%).
    ai_nudge is a signed integer in [-10, +10] representing a percentage-point adjustment.
    """
    ai_pct  = max(-10.0, min(10.0, float(ai_nudge)))
    blended = (base_score * 0.75) + ((base_score + ai_pct) * 0.25)
    return round(min(100.0, max(0.0, blended)), 1)

# ---------------------------------------------------------------------------
# Prompt builder (shared by both Gemini and ChatGPT callers)
# ---------------------------------------------------------------------------

def build_prompt(alert_id: str, alert: dict, base_score: float,
                 user_profile: dict | None = None) -> str:
    """
    Build a compact LLM forensic-analysis prompt.

    Sends only what the model needs:
      - Core alert scalars (user, action, asset, risk score, qpc_signature)
      - The alertedUser's baseline profile (role, working hours, normal_bytes,
        daily_limit_bytes, approved assets) so the AI can compute anomaly multipliers
      - Deduplicated risk-reason tags
      - A per-event breakdown table with actor, bytes, and causal metadata
      - Pre-computed base risk to calibrate the nudge
    """
    payload  = alert["triggeringEvent"]["payload"]
    historic = alert.get("historicActions", [])

    # --- aggregate risk reasons (deduplicated) ---
    all_reasons: set[str] = set()
    for ev in historic:
        all_reasons.update(ev.get("riskReasons", []))

    # --- compact historic digest ---
    from collections import Counter
    action_counts: Counter = Counter()
    unique_assets: set[str] = set()
    total_bytes   = 0
    timestamps    = []
    for ev in historic:
        action_counts[ev.get("action", "UNKNOWN")] += 1
        if ev.get("target_asset"):
            unique_assets.add(ev["target_asset"])
        total_bytes += ev.get("payload", {}).get("bytes_transferred", 0)
        ts = ev.get("timestamp") or ev.get("payload", {}).get("timestamp")
        if ts:
            timestamps.append(ts)

    action_summary = ", ".join(f"{act}×{cnt}" for act, cnt in action_counts.most_common())
    asset_list     = ", ".join(sorted(unique_assets)) or "N/A"
    bytes_human    = (
        f"{total_bytes / 1_073_741_824:.2f} GB" if total_bytes >= 1_073_741_824 else
        f"{total_bytes / 1_048_576:.1f} MB"     if total_bytes >= 1_048_576     else
        f"{total_bytes / 1_024:.1f} KB"         if total_bytes >= 1_024         else
        f"{total_bytes} B"
    )
    if len(timestamps) >= 2:
        time_window = f"{min(timestamps)} → {max(timestamps)}"
    elif timestamps:
        time_window = timestamps[0]
    else:
        time_window = "N/A"

    # --- per-event detail rows (capped at 8 to stay compact) ---
    # Rules: no duplicate payload fields, no raw signature strings.
    # Include source_user when it differs (cross-actor events), metadata key-values
    # that add causal context (e.g. granted_to for ticket approvals).
    alerted_user = alert.get("alertedUser", "")

    def _bytes_human(b: int) -> str:
        if b >= 1_073_741_824: return f"{b/1_073_741_824:.2f} GB"
        if b >= 1_048_576:     return f"{b/1_048_576:.1f} MB"
        if b >= 1_024:         return f"{b/1_024:.1f} KB"
        return f"{b} B"

    # Only keep metadata keys that add investigative value (skip empty/noise keys)
    _META_KEYS = {"granted_to", "revoked_from", "ticket_id",
                  "approved_by", "reason", "target_user", "privilege", "granted_privelege", "privelege_event_id"}

    event_rows = []
    for ev in historic[:8]:
        ts     = ev.get("timestamp", "")[:16]
        action = ev.get("action", "?")
        asset  = ev.get("target_asset", "?")
        # bytes lives in payload to avoid top-level duplication
        byt    = _bytes_human(ev.get("payload", {}).get("bytes_transferred", 0))

        # source_user — only show when it's a different actor (cross-actor events)
        src_user = ev.get("payload", {}).get("source_user", "") or ev.get("source_user", "")
        actor_part = f" by {src_user}" if src_user and src_user != alerted_user else ""

        # risk reasons — strip the parenthetical value to keep it short
        # e.g. "UNAUTH_ASSET(Finance_DB)" → "UNAUTH_ASSET"
        raw_reasons = ev.get("riskReasons", [])
        short_reasons = ", ".join(r.split("(")[0] for r in raw_reasons) or "-"

        # metadata — include only investigatively useful key-value pairs
        meta = ev.get("metadata") or ev.get("payload", {}).get("metadata") or {}
        meta_parts = [f"{k}={v}" for k, v in meta.items()
                      if k in _META_KEYS and v and str(v).strip()]
        meta_str = f"  {{{', '.join(meta_parts)}}}" if meta_parts else ""

        event_rows.append(
            f"  {ts}  {action:<22} {asset:<25}{actor_part}"
            f"  {byt:>10}  [{short_reasons}]{meta_str}"
        )
    event_table = "\n".join(event_rows) if event_rows else "  (none)"

    # --- user baseline profile block ---
    if user_profile:
        p = user_profile
        normal_bytes_human = _bytes_human(p.get("normal_bytes", 0))
        daily_limit_human = _bytes_human(p.get("daily_limit_bytes", p.get("normal_bytes", 0) * 5))
        approved = ", ".join(p.get("assets", [])) or "none"
        profile_block = (
            f"User Baseline Profile:\n"
            f"  Role           : {p.get('role', 'unknown')}\n"
            f"  Working Hours  : {p.get('start_hour', '?')}:00Z – {p.get('end_hour', '?')}:00Z\n"
            f"  Normal Transfer: {normal_bytes_human} per operation\n"
            f"  Daily Limit    : {daily_limit_human}\n"
            f"  Approved Assets: {approved}\n\n"
        )
    else:
        profile_block = ""

    return (
        "You are a cybersecurity forensic analyst for a quantum-safe banking SIEM.\n\n"
        "Analyze this security alert and return a JSON object with EXACTLY these fields:\n"
        '1. "eventSummary": One sentence (max 20 words) describing the core issue, citing the user, the asset, and crucial context (e.g., who was granted privilege, if it lacked approval, or if the signature was tampered/unverified).\n'
        '2. "triggeringQuery": A natural language forensic narrative describing the timeline, '
        'specific users, assets/databases, and exact byte counts involved (do not mention 0 bytes for administrative actions like APPROVED_TICKET or GRANTED_PRIVILEGE).\n'
        '3. "riskNudge": Integer -10..+10 — your risk adjustment.\n'
        '4. "maliciousIndicators": Array of {"title", "description"} objects. '
        'Each description MUST cite specific users, assets, byte counts (only if > 0), or timestamps from the data below. '
        'Include 2-4 indicators. If signatureVerified is false, include that as a malicious indicator (e.g. "Cryptographic Signature tampered"). '
        'CRITICAL: If "granted_privelege" is in the metadata or risk reasons show GRANTED_SPECIAL_ACCESS, do NOT flag it as unauthorized asset access, don\'t mention at malicious indicator '
        'Empty array if none.\n'
        '5. "benignFactors": Array of {"title", "description"} objects.\n'
        'A benign factor must actively REDUCE the suspiciousness of the specific anomalous behaviour observed.\n'
        'It must be grounded in the event data provided, not inferred from the baseline profile.\n'
        'STRICT EXCLUSIONS — never use these as benign factors:\n'
        '  - The user has a role (every user has a role; that is not mitigating)\n'
        '  - The user has approved access to an asset (baseline access is a precondition, not a mitigation)\n'
        '  - The transfer volume is within normal range (if risk reasons say HIGH_VOLUME, it is not within range)\n'
        '  - Verified cryptographic signature (neutral technical fact, not evidence of legitimacy)\n'
        'ACCEPTABLE benign factors (only if the evidence is actually present in the data):\n'
        '  - A formal privilege grant exists in the event metadata authorising the specific action (e.g., granted_privelege)\n'
        '  - The event metadata contains explicit business justification\n'
        '  - The historic events show a long, unbroken, low-risk access pattern with no prior anomaly flags\n'
        'If no genuinely mitigating factor exists in the event data, return an empty array [].\n\n'
        f"Alert ID      : {alert_id}\n"
        f"User          : {alert['alertedUser']}\n"
        f"Action        : {payload.get('action')}\n"
        f"Asset         : {payload.get('target_asset')}\n"
        f"Bytes         : {_bytes_human(payload.get('bytes_transferred', 0))}\n"
        f"Risk Score    : {alert['riskScore']} pts\n"
        f"Sig Verified  : {alert['triggeringEvent']['signatureVerified']}\n"
        f"Metadata      : {payload.get('metadata', {})}\n"
        f"Risk Reasons  : {', '.join(all_reasons) or 'none'}\n"
        f"Base Risk     : {base_score}%\n\n"
        f"{profile_block}"
        "Historic Events (timestamp  action  asset  actor  bytes  [risk tags]  {metadata}):\n"
        f"{event_table}\n\n"
        "Return ONLY valid JSON, no markdown."
    )

# ---------------------------------------------------------------------------
# AI caller — Groq
# ---------------------------------------------------------------------------

# Model to use. llama-3.3-70b-versatile is fast, cheap, and supports JSON mode.
GROQ_MODEL = "llama-3.3-70b-versatile"


def call_groq(prompt: str) -> dict | None:
    """
    Call Groq's chat-completions endpoint with JSON-mode enforced.
    Returns a parsed dict or None on failure / missing key.
    """
    if not GROQ_API_KEY:
        return None
    try:
        from groq import Groq

        client = Groq(api_key=GROQ_API_KEY)
        resp   = client.chat.completions.create(
            model           = GROQ_MODEL,
            messages        = [
                {
                    "role"   : "system",
                    "content": "You are a cybersecurity forensic analyst. Output ONLY valid JSON.",
                },
                {"role": "user", "content": prompt},
            ],
            response_format = {"type": "json_object"},
            temperature     = 0.2,
            max_tokens      = 800,   # enough for triggeringQuery + 4 detailed indicators
        )
        return json.loads(resp.choices[0].message.content)
    except Exception as exc:
        print(f"  [WARN] Groq call failed: {exc}")
        return None

# ---------------------------------------------------------------------------
# Core enrichment
# ---------------------------------------------------------------------------

def enrich_alert(alert_id: str, alert_dict: dict) -> dict:
    """
    Attach riskPercentage, severityLevel, eventSummary, triggeringQuery,
    maliciousIndicators, and benignFactors to alert_dict in-place, then return it.

    Enrichment strategy:
      1. Call Groq if GROQ_API_KEY is set.
      2. If Groq unavailable/fails, fall back to expert-curated manual values (ENRICHMENT).
      3. If no manual values exist, use generic fallback.
    """
    # Compute base score from the alert's live UEBA data (deterministic, no AI)
    base_score = compute_base_score(alert_dict)
    print(f"    Computed base score for {alert_id}: {base_score}%")

    # Fetch the alertedUser's baseline profile to send to the AI
    user_profile = _BASE_BEHAVIOUR.get(alert_dict.get("alertedUser", ""))

    prompt  = build_prompt(alert_id, alert_dict, base_score, user_profile)
    ai_resp = None

    if GROQ_API_KEY:
        print(f"    Calling Groq ({GROQ_MODEL}) for {alert_id}...")
        ai_resp = call_groq(prompt)
        if ai_resp:
            print(f"    Enriched {alert_id} via Groq.")

    def _parse_indicator_list(raw) -> list[dict]:
        """Accept a list of {title, description} dicts; skip malformed entries."""
        if not isinstance(raw, list):
            return []
        out = []
        for item in raw:
            if isinstance(item, dict) and item.get("title") and item.get("description"):
                out.append({"title": item["title"], "description": item["description"]})
        return out

    ai_nudge = 0

    if ai_resp:
        ai_nudge = int(ai_resp.get("riskNudge", 0))
        
        event_summary    = ai_resp.get("eventSummary", f"Suspicious activity by {alert_dict.get('alertedUser', 'unknown user')}")
        print("Ai_summary", event_summary, ai_resp)
        triggering_query = ai_resp.get("triggeringQuery", "No additional context available.")
        malicious        = _parse_indicator_list(ai_resp.get("maliciousIndicators"))
        benign           = _parse_indicator_list(ai_resp.get("benignFactors"))
    else:
        prev_data = {}
        try:
            report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alerts_report.json")
            if os.path.exists(report_path):
                with open(report_path, "r", encoding="utf-8") as f:
                    for pa in json.load(f):
                        if pa.get("alertId") == alert_id:
                            prev_data = pa
                            break
        except Exception:
            pass

        if "eventSummary" in prev_data:
            event_summary    = prev_data["eventSummary"]
            triggering_query = prev_data.get("triggeringQuery", "No additional context available.")
            malicious        = prev_data.get("maliciousIndicators", [])
            benign           = prev_data.get("benignFactors", [])
        else:
            final_risk = compute_risk_pct(base_score, 0)
            alert_dict["riskPercentage"]      = final_risk
            alert_dict["severityLevel"]       = assign_severity(final_risk)
            alert_dict["eventSummary"]        = f"Suspicious activity by {alert_dict.get('alertedUser', 'unknown user')}"
            alert_dict["triggeringQuery"]     = "No additional context available."
            alert_dict["maliciousIndicators"] = []
            alert_dict["benignFactors"]       = []
            return alert_dict

    final_risk = compute_risk_pct(base_score, ai_nudge)
    severity   = assign_severity(final_risk)

    alert_dict["riskPercentage"]      = final_risk
    alert_dict["severityLevel"]       = severity
    alert_dict["eventSummary"]        = event_summary
    alert_dict["triggeringQuery"]     = triggering_query
    alert_dict["maliciousIndicators"] = malicious
    alert_dict["benignFactors"]       = benign
    return alert_dict

# ---------------------------------------------------------------------------
# Startup banner helper
# ---------------------------------------------------------------------------

def log_ai_key_status() -> bool:
    """
    Print a human-readable banner describing which AI keys are active.
    Returns True if GROQ_API_KEY is set, False for manual-only mode.
    """
    if GROQ_API_KEY:
        print(f"[*] GROQ_API_KEY found — AI enrichment enabled ({GROQ_MODEL}).")
    else:
        print("[*] No GROQ_API_KEY set — running manual-only enrichment.")
    return bool(GROQ_API_KEY)

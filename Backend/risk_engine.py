"""
=============================================================================
  QUANTUM-SAFE FORENSICS — UEBA Risk Engine (Sliding Window Detector)
=============================================================================
  Implements:
    Step 1: Baseline Heuristics Lookup   — pull user Normal Profile
    Step 2: Per-Event Risk Scoring       — compare payload vs. baseline
    Step 3: 12-Hour Sliding Window       — accumulate & decay risk buckets
    Step 4: Threshold Trigger            — fire CRITICAL alert at >= 150 pts
    Step 5: Handoff payload              — yield alert context to Graph Engine
=============================================================================
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
WINDOW_HOURS        = 12          # Sliding window duration
ALERT_THRESHOLD     = 100         # Total risk points that trigger a CRITICAL alert

# Risk point values per rule
RISK_OFF_HOURS        = 20        # Action outside normal working hours
RISK_RARE_ACTION      = 25        # Action marked as "rare" for this user's role
RISK_HIGH_VOLUME      = 50        # bytes_transferred > daily limit
RISK_UNAUTH_ASSET     = 30        # Target asset NOT in user's approved asset list
RISK_GRANTED_BUT_OUT_OF_PROFILE_ASSETS = 5  # Target asset is NOT in user's baseline behavior asset list
RISK_UNAPPROVED_PRIVILEGE = 100       # Target asset is a PRIVILEGE not approved for the user
RISK_UNVERIFIED_SIG   = 180       # Cryptographic signature verification failed

# Actions considered "rare" for each role
RARE_ACTIONS_BY_ROLE = {
    "Admin":      ["GRANTED_PRIVILEGE"],
    "Contractor": ["GRANTED_PRIVILEGE", "REVOKED_PRIVILEGE", "APPROVED_TICKET"],
    "Employee":   ["GRANTED_PRIVILEGE", "REVOKED_PRIVILEGE", "APPROVED_TICKET"],
    "HR":         ["GRANTED_PRIVILEGE", "REVOKED_PRIVILEGE", "APPROVED_TICKET"],
    "Finance":    ["GRANTED_PRIVILEGE", "REVOKED_PRIVILEGE", "APPROVED_TICKET"],
}

# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class RiskEvent:
    """A single scored event that lives inside a user's sliding window bucket."""
    log_id:    str
    timestamp: datetime
    action:    str
    asset:     str
    points:    int
    reasons:   list
    metadata:  dict = field(default_factory=dict)
    bytes_tx:  int = 0


@dataclass
class Alert:
    """Fired when a user's bucket overflows the threshold."""
    user:                str
    triggered_log:       str
    triggered_asset:     str
    triggered_ts:        datetime
    window_total:        int
    contributing_events: list

    def summary(self) -> str:
        lines = [
            "",
            "=" * 66,
            "  [!!] CRITICAL BEHAVIORAL ALERT",
            "=" * 66,
            f"  User         : {self.user}",
            f"  Trigger Log  : {self.triggered_log}",
            f"  Asset        : {self.triggered_asset}",
            f"  Timestamp    : {self.triggered_ts.strftime('%Y-%m-%dT%H:%M:%SZ')}",
            f"  Window Total : {self.window_total} pts  (threshold: {ALERT_THRESHOLD} pts)",
            "-" * 66,
            "  Contributing Events in 12-Hour Window:",
        ]
        for ev in self.contributing_events:
            ts_str = ev.timestamp.strftime("%Y-%m-%d %H:%MZ")
            reasons_str = ", ".join(ev.reasons)
            lines.append(
                f"    [{ts_str}] {ev.log_id:10s} +{ev.points:>3}pts  {reasons_str}"
            )
        lines.append("=" * 66)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Risk Engine
# ---------------------------------------------------------------------------

class RiskEngine:
    """
    Streaming UEBA risk engine.

    Usage:
        engine = RiskEngine(base_behaviour)
        for log in sorted_logs:
            alert = engine.process(log)
            if alert:
                handle_alert(alert)
    """

    def __init__(self, base_behaviour: dict):
        self._profiles: dict = base_behaviour["USERS"]
        # Per-user list of RiskEvent objects (the sliding window bucket)
        self._buckets: dict = defaultdict(list)
        # Track the timestamp of the last fired alert per user (for 12-hr cooldown)
        self._last_alert_ts: dict[str, datetime] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process(self, log: dict, signature_verified: bool) -> Optional[Alert]:
        """
        Process a single log entry through the UEBA pipeline.

        Returns an Alert if the sliding-window threshold is breached,
        otherwise returns None.
        """
        payload   = log["payload"]
        log_id    = log["log_id"]
        user      = payload["source_user"]
        asset     = payload["target_asset"]
        action    = payload["action"]
        bytes_tx  = payload.get("bytes_transferred", 0)
        metadata  = payload.get("metadata", {})
        ts        = self._parse_ts(payload["timestamp"])

        # Step 1: Pull baseline profile
        profile = self._profiles.get(user)
        if profile is None:
            # Unknown user — zero-trust, assign fixed penalty
            event = RiskEvent(log_id, ts, action, asset, 50, ["UNKNOWN_USER"], metadata, bytes_tx)
            self._slide_and_insert(user, event, ts)
            return self._check_threshold(user, log_id, asset, ts)

        # Step 2: Score this event
        points, reasons = self._score_event(
            profile, action, asset, bytes_tx, ts, metadata, self._buckets[user], signature_verified
        )

        event = RiskEvent(log_id, ts, action, asset, points, reasons, metadata, bytes_tx)

        # Step 3: Slide the window and insert
        self._slide_and_insert(user, event, ts)

        # Step 4: Check threshold
        return self._check_threshold(user, log_id, asset, ts)

    def get_bucket(self, user: str) -> list:
        """Return the current sliding window bucket for a user (snapshot)."""
        return list(self._buckets[user])

    def bucket_total(self, user: str) -> int:
        """Return the current accumulated risk score for a user."""
        return sum(e.points for e in self._buckets[user])

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_ts(ts_str: str) -> datetime:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))

    def _score_event(
        self,
        profile:  dict,
        action:   str,
        asset:    str,
        bytes_tx: int,
        ts:       datetime,
        metadata: dict,
        bucket:   list,
        signature_verified: bool,
    ):
        """Apply all scoring rules and return (total_points, [reasons])."""
        points  = 0
        reasons = []

        # Rule 1 — Off-hours check
        hour = ts.hour  # UTC hour
        if not (profile["start_hour"] <= hour <= profile["end_hour"]):
            points  += RISK_OFF_HOURS
            reasons.append(f"OFF_HOURS({hour:02d}:00Z)")

        # Rule 2 — Rare action check
        role = profile.get("role", "Employee")
        rare_actions = RARE_ACTIONS_BY_ROLE.get(role, [])
        if action in rare_actions:
            points  += RISK_RARE_ACTION
            reasons.append(f"RARE_ACTION({action})")

        # Rule 3 — Volume anomaly (> daily limit)
        window_bytes = sum(e.bytes_tx for e in bucket) + bytes_tx
        daily_limit = profile.get("daily_limit_bytes", profile.get("normal_bytes", 5000) * 5)
        if window_bytes > daily_limit:
            points  += round((window_bytes / daily_limit) * RISK_HIGH_VOLUME)
            reasons.append(f"HIGH_VOLUME({window_bytes}B vs {daily_limit}B limit)")

        # Rule 4 — Unauthorized asset
        approved_assets = profile.get("assets", [])
        if asset not in approved_assets:
            
            # Apply granted_privelege mitigation ONLY if the asset is unauthorized
            if metadata.get("granted_privelege"):
                points += RISK_GRANTED_BUT_OUT_OF_PROFILE_ASSETS
                reasons.append(f"GRANTED_SPECIAL_ACCESS({asset})")
            else:
                points += RISK_UNAUTH_ASSET
                reasons.append(f"UNAUTH_ASSET({asset})")

        # Rule 5 — Unapproved Privilege Grant
        if action == "GRANTED_PRIVILEGE" and not metadata.get("approval_id"):
            points += RISK_UNAPPROVED_PRIVILEGE
            reasons.append("UNAPPROVED_GRANT")

        # Rule 6 — Unverified Signature
        if not signature_verified:
            points += RISK_UNVERIFIED_SIG
            reasons.append("UNVERIFIED_SIGNATURE")

        # Clamp total to zero minimum (safety net — should not normally trigger)
        points = max(0, points)

        return points, reasons

    def _slide_and_insert(self, user: str, event: RiskEvent, current_ts: datetime) -> None:
        """Expire events older than WINDOW_HOURS, then insert the new event."""
        cutoff = current_ts - timedelta(hours=WINDOW_HOURS)
        self._buckets[user] = [
            e for e in self._buckets[user] if e.timestamp > cutoff
        ]
        # Only track events that contribute risk points
        if event.points > 0:
            self._buckets[user].append(event)

    def _check_threshold(self, user: str, log_id: str, asset: str, ts: datetime) -> Optional[Alert]:
        """Fire an Alert if bucket total >= ALERT_THRESHOLD and the user has not
        already triggered an alert within the current 12-hour window."""
        total = self.bucket_total(user)
        if total < ALERT_THRESHOLD:
            return None

        last_ts = self._last_alert_ts.get(user)
        if last_ts is not None and (ts - last_ts) < timedelta(hours=WINDOW_HOURS):
            # Same window — suppress duplicate alert
            return None

        self._last_alert_ts[user] = ts
        return Alert(
            user                = user,
            triggered_log       = log_id,
            triggered_asset     = asset,
            triggered_ts        = ts,
            window_total        = total,
            contributing_events = list(self._buckets[user]),
        )


# ---------------------------------------------------------------------------
# Standalone runner
# ---------------------------------------------------------------------------

def run_engine(logs_path: str, behaviour_path: str):
    with open(logs_path,      encoding="utf-8") as f:
        logs = json.load(f)
    with open(behaviour_path, encoding="utf-8") as f:
        behaviour = json.load(f)

    # Sort by timestamp — crucial for the sliding window to work correctly
    logs.sort(key=lambda x: x["payload"]["timestamp"])

    from main import _verify_signature
    engine = RiskEngine(behaviour)
    alerts = []
    for log in logs:
        verified = _verify_signature(log.get("qpc_signature", ""), log.get("payload", {}))
        alert = engine.process(log, signature_verified=verified)
        if alert:
            alerts.append(alert)
            print(alert.summary())

    print(f"\n[Risk Engine] Processed {len(logs)} logs -> {len(alerts)} alert(s) fired.")
    return alerts


if __name__ == "__main__":
    import os
    base = os.path.dirname(os.path.abspath(__file__))
    run_engine(
        os.path.join(base, "synthetic_banking_logs.json"),
        os.path.join(base, "base_behaviour.json"),
    )

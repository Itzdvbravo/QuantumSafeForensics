import json
import random
from datetime import datetime, timedelta
import hashlib
import itertools

from dilithium_py.dilithium import Dilithium2

# ==========================================
# CONFIGURATION SECTION: Modify these to customize your dataset
# ==========================================

# 1. Define Available Actions
STANDARD_ACTIONS = ["AUTHENTICATED_TO", "QUERIED", "EXPORTED_FILE", "LOGGED_OUT"]
ADMIN_ACTIONS = ["APPROVED_TICKET", "REVOKED_PRIVILEGE"]

# 2. Load Assets, Users, and Scenario Events
with open("assets.json", "r") as f:
    ASSETS = json.load(f)

with open("base_behaviour.json", "r") as f:
    USERS = json.load(f)

with open("scenario_data.json", "r") as f:
    scenario_data = json.load(f)

anomaly_scenario_events_list = scenario_data["scenario_events_list"]


# ==========================================

USE_REAL_QPC = True

if USE_REAL_QPC:
    print("Generating logger QPC keys (Dilithium2)...")
    LOGGER_PK, LOGGER_SK = Dilithium2.keygen()
    with open("logger_public_key.hex", "w") as f:
        f.write(LOGGER_PK.hex())

def generate_qpc_signature(payload_string):
    """Generates a 'Quantum-Proof' signature (either real Dilithium2 or mock based on USE_REAL_QPC)."""
    if USE_REAL_QPC:
        sig = Dilithium2.sign(LOGGER_SK, payload_string.encode('utf-8'))
        return sig.hex()
    else:
        hashed = hashlib.sha256(payload_string.encode()).hexdigest()
        return f"QPC-CRYSTALS-Dilithium-{hashed[:16]}...[VERIFIED]"



def generate_background_noise(start_date, days=30):
    logs = []
    log_id_counter = 1000
    current_permissions = {u: {asset: None for asset in profile["assets"]} for u, profile in USERS.items()}

    for day in range(days):
        current_date = start_date + timedelta(days=day)

        # Skip weekends to make it look realistic
        if current_date.weekday() >= 5:
            continue

        for user, profile in USERS.items():
            daily_bytes_used = 0
            # Determine daily event count based on user role
            role = profile.get("role")
            if role == "Admin":
                num_events = random.randint(1, 4)
            elif role == "HR":
                num_events = random.randint(2, 6)
            elif role == "Finance":
                num_events = random.randint(2, 4)
            else:
                num_events = random.randint(3, 8)

            events_generated = 0
            while events_generated < num_events:
                # Pick a random time within their normal working hours
                hour = random.randint(profile["start_hour"], profile["end_hour"])
                minute = random.randint(0, 59)
                event_time = current_date.replace(hour=hour, minute=minute)

                available_assets = list(current_permissions[user].keys())
                if not available_assets:
                    events_generated += 1
                    continue
                asset = random.choice(available_assets)

                # Admins occasionally do admin things, otherwise do standard things
                if profile["role"] == "Admin" and random.random() > 0.85:
                    action_choices = ADMIN_ACTIONS.copy()
                    # If this is the last slot, don't choose APPROVED_TICKET as it adds a second event (GRANTED_PRIVILEGE)
                    if events_generated == num_events - 1 and "APPROVED_TICKET" in action_choices:
                        action_choices.remove("APPROVED_TICKET")
                    
                    if not action_choices:
                        action = random.choice(STANDARD_ACTIONS)
                        if action in ["QUERIED", "EXPORTED_FILE"]:
                            max_allowed = profile.get("daily_limit_bytes", profile["normal_bytes"]) - daily_bytes_used
                            if max_allowed > 0:
                                upper = min(profile["normal_bytes"], max_allowed)
                                lower = min(100, upper)
                                bytes_transferred = random.randint(lower, upper)
                                daily_bytes_used += bytes_transferred
                            else:
                                bytes_transferred = 0
                        else:
                            bytes_transferred = 0
                        metadata = {}
                    else:
                        action = random.choice(action_choices)
                        bytes_transferred = 0
                        # Build metadata for admin actions
                        all_users = [u for u in USERS.keys() if u != user]
                        
                        if action == "APPROVED_TICKET":
                            valid_combos = []
                            for tu in all_users:
                                for tr in ASSETS:
                                    if tr not in current_permissions[tu] and tr != "Admin_Gateway" and tr != "Jira":
                                        valid_combos.append((tu, tr))
                            if not valid_combos:
                                continue
                            target_user, target_resource = random.choice(valid_combos)
                            metadata = {
                                "granted_to": target_user
                            }
                            asset = target_resource
                            # Will add to current_permissions after knowing the grant_log_id
                        elif action == "REVOKED_PRIVILEGE":
                            valid_combos = []
                            for tu in all_users:
                                for tr in ASSETS:
                                    if tr in current_permissions[tu]:
                                        valid_combos.append((tu, tr))
                            if not valid_combos:
                                continue
                            target_user, target_resource = random.choice(valid_combos)
                            metadata = {
                                "revoked_from": target_user
                            }
                            asset = target_resource
                            if target_resource in current_permissions[target_user]:
                                del current_permissions[target_user][target_resource]
                        else:
                            metadata = {}
                else:
                    action = random.choice(STANDARD_ACTIONS)
                    if action in ["QUERIED", "EXPORTED_FILE"]:
                        max_allowed = profile.get("daily_limit_bytes", profile["normal_bytes"]) - daily_bytes_used
                        if max_allowed > 0:
                            upper = min(profile["normal_bytes"], max_allowed)
                            lower = min(100, upper)
                            bytes_transferred = random.randint(lower, upper)
                            daily_bytes_used += bytes_transferred
                        else:
                            bytes_transferred = 0
                    else:
                        bytes_transferred = 0
                    metadata = {}

                # If the user is accessing an asset they gained permission to dynamically:
                asset_grant_id = current_permissions[user].get(asset)
                if asset_grant_id is not None:
                    metadata["granted_privelege"] = True
                    metadata["privelege_event_id"] = asset_grant_id

                payload = {
                    "timestamp": event_time.isoformat() + "Z",
                    "source_user": user,
                    "target_asset": asset,
                    "action": action,
                    "bytes_transferred": bytes_transferred,
                    "metadata": metadata
                }

                logs.append({
                    "log_id": f"LOG-{log_id_counter}",
                    "payload": payload,
                    "qpc_signature": generate_qpc_signature(json.dumps(payload))
                })
                log_id_counter += 1
                events_generated += 1

                # If this was an APPROVED_TICKET, follow up with GRANTED_PRIVILEGE
                if action == "APPROVED_TICKET":
                    grant_log_id = f"LOG-{log_id_counter}"
                    # Update dynamic permissions mapping
                    current_permissions[metadata["granted_to"]][asset] = grant_log_id

                    grant_time = event_time + timedelta(minutes=random.randint(1, 15))
                    grant_metadata = {
                        "granted_to": metadata["granted_to"],
                        "approval_id": f"LOG-{log_id_counter - 1}"
                    }
                    grant_payload = {
                        "timestamp": grant_time.isoformat() + "Z",
                        "source_user": user,
                        "target_asset": asset,
                        "action": "GRANTED_PRIVILEGE",
                        "bytes_transferred": 0,
                        "metadata": grant_metadata
                    }
                    logs.append({
                        "log_id": grant_log_id,
                        "payload": grant_payload,
                        "qpc_signature": generate_qpc_signature(json.dumps(grant_payload))
                    })
                    log_id_counter += 1
                    events_generated += 1

    return logs, log_id_counter


def inject_anomaly_scenario(logs, log_id_counter, attack_date, scenario_index=0):
    """Injects the exact scenario we mapped out in the architecture."""

    scenario_events = anomaly_scenario_events_list[scenario_index]
    approval_ids = {}  # (target_user, asset) -> approval_log_id
    grant_ids = {}     # (target_user, asset) -> grant_log_id

    for event in scenario_events:
        time_parts = list(map(int, event["time"].split(":")))
        event_time = attack_date.replace(hour=time_parts[0], minute=time_parts[1], second=time_parts[2])

        metadata = event["meta"].copy()
        user = event["user"]
        asset = event["asset"]
        action = event["action"]
        current_log_id = f"LOG-{log_id_counter}"

        if action == "APPROVED_TICKET":
            target_user = metadata.get("granted_to")
            if target_user:
                approval_ids[(target_user, asset)] = current_log_id
        elif action == "GRANTED_PRIVILEGE":
            target_user = metadata.get("granted_to")
            if target_user:
                grant_ids[(target_user, asset)] = current_log_id
                app_id = approval_ids.get((target_user, asset))
                if app_id:
                    metadata["approval_id"] = app_id
        elif action == "REVOKED_PRIVILEGE":
            target_user = metadata.get("revoked_from")
            if target_user:
                if (target_user, asset) in grant_ids:
                    del grant_ids[(target_user, asset)]
        else:
            if (user, asset) in grant_ids:
                metadata["granted_privelege"] = True
                metadata["privelege_event_id"] = grant_ids[(user, asset)]

        payload = {
            "timestamp": event_time.isoformat() + "Z",
            "source_user": user,
            "target_asset": asset,
            "action": action,
            "bytes_transferred": event["bytes"],
            "metadata": metadata
        }

        qpc_signature = generate_qpc_signature(json.dumps(payload))
        if event.get("invalid_qpc", False):
            # Tamper the signature to simulate invalid QPC
            qpc_signature = "INVALID_" + qpc_signature

        logs.append({
            "log_id": current_log_id,
            "payload": payload,
            "qpc_signature": qpc_signature
        })
        log_id_counter += 1

    return logs, log_id_counter


def main():
    start_date = datetime(2026, 6, 1)  # Start June 1st

    print("Generating background noise...")
    logs, counter = generate_background_noise(start_date, days=90)

    attack_dates = [datetime(2026, 6, 20), datetime(2026, 6, 25), datetime(2026, 6, 28), datetime(2026, 7, 2)]
    for i, attack_date in enumerate(attack_dates):
        if i < len(anomaly_scenario_events_list):
            print(f"Injecting anomaly scenario {i+1} on {attack_date.strftime('%Y-%m-%d')}...")
            logs, counter = inject_anomaly_scenario(logs, counter, attack_date, scenario_index=i)

    # Sort logs chronologically so they look like a real database dump
    logs.sort(key=lambda x: x["payload"]["timestamp"])

    # Save to a JSON file
    filename = "synthetic_banking_logs.json"
    with open(filename, "w") as f:
        json.dump(logs, f, indent=2)

    print(f"Successfully generated {len(logs)} logs and saved to {filename}.")
    print(f"Use synthetic_bank_logs.json and logger_public_key.hex to generate alerts.")


if __name__ == "__main__":
    main()

# charlie limit vs the limit given in anomaly
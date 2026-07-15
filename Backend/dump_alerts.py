import json

with open("alerts_report.json", "r") as f:
    alerts = json.load(f)

with open("alerts_dump.txt", "w", encoding="utf-8") as out:
    for a in alerts:
        out.write(f"\n{'='*40}\n")
        out.write(f"Alert ID: {a['alertId']} | User: {a['alertedUser']} | Score: {a['riskScore']}\n")
        te = a['triggeringEvent']
        out.write(f"Triggering Event: {te['payload'].get('action', 'Unknown')} on {te['payload'].get('target_asset', 'Unknown')}\n")
        out.write("Risk Reasons for last event:\n")
        last_event = a['historicActions'][-1]
        out.write(str(last_event['riskReasons']) + "\n")
        out.write(f"Total Bytes: {sum(h['payload'].get('bytes_transferred', 0) for h in a['historicActions'])}\n")

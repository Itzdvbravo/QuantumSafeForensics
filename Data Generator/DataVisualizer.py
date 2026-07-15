import json
import networkx as nx
from pyvis.network import Network


def build_interactive_graph(json_file):
    print(f"Loading 30 days of data from {json_file}...")
    with open(json_file, 'r') as f:
        logs = json.load(f)

    G = nx.DiGraph()
    edge_groups = {}  # We use this to group multiple logs into a single edge

    # Helper function to group logs
    def add_to_group(src, tgt, label, html_info):
        key = (src, tgt, label)
        if key not in edge_groups:
            edge_groups[key] = []
        edge_groups[key].append(html_info)

    print(f"Found {len(logs)} total events. Aggregating month-long data...")

    # 1. Parse and Aggregate all logs
    for log in logs:
        payload = log["payload"]
        user = payload["source_user"]
        asset = payload["target_asset"]
        action = payload["action"]
        timestamp = payload["timestamp"].replace("T", " ").replace("Z", "")
        meta = payload.get("metadata", {})

        # Build a single line of info for this specific event using plain text
        log_info = f"• {timestamp}"
        if "bytes_transferred" in payload and payload["bytes_transferred"] > 0:
            log_info += f" | Vol: {payload['bytes_transferred'] / 1e6:.1f} MB"
        if "qpc_signature" in log:
            log_info += " [QPC Valid]"

        if action in ["APPROVED_TICKET", "REVOKED_PRIVILEGE"]:
            # Admin to Ticket
            add_to_group(user, asset, action, log_info)

            # Ticket to Target User
            target_user = meta.get("granted_to") or meta.get("revoked_from")
            if target_user:
                target_resource = meta.get("resource", "Unknown")
                auth_label = "AUTHORIZES" if action == "APPROVED_TICKET" else "REVOKES"
                auth_info = f"• {timestamp} | Target: {target_resource} [QPC Valid]"
                add_to_group(asset, target_user, auth_label, auth_info)
        else:
            add_to_group(user, asset, action, log_info)

    # Helper function to style nodes correctly based on their name
    def add_node_safe(node_id):
        if node_id not in G:
            if "Ticket_" in node_id:
                G.add_node(node_id, label=node_id.replace("Ticket_", ""), title=f"Context Ticket:\n{node_id}",
                           color="#fddb92", shape="square", size=20)
            elif "Admin" in node_id:
                G.add_node(node_id, label=node_id, title=f"Admin Identity:\n{node_id}", color="#ff9a9e", shape="dot",
                           size=25)
            elif "User" in node_id or "Contractor" in node_id:
                G.add_node(node_id, label=node_id, title=f"Standard Identity:\n{node_id}", color="#a1c4fd", shape="dot",
                           size=25)
            else:
                G.add_node(node_id, label=node_id, title=f"System Asset:\n{node_id}", color="#c2e9fb", shape="database",
                           size=30)

    # 2. Build the Graph from the aggregated groups
    for (src, tgt, label), events in edge_groups.items():
        add_node_safe(src)
        add_node_safe(tgt)

        count = len(events)
        display_label = label if count == 1 else f"{label} (x{count})"

        # Limit to the last 15 events so the tooltip doesn't become too tall
        display_events = events[-15:]

        # Construct the plain text tooltip for the edge
        tooltip = f"Action: {label}\n"
        tooltip += f"Total Occurrences: {count}\n"
        tooltip += "-" * 30 + "\n"
        tooltip += "\n".join(display_events)

        if count > 15:
            tooltip += f"\n\n...and {count - 15} previous events hidden"

        # Add the edge to the graph
        G.add_edge(src, tgt, label=display_label, title=tooltip)

    # --- PYVIS VISUALIZATION SETUP ---
    net = Network(height="800px", width="100%", bgcolor="#0b1519", font_color="#ffffff", directed=True)
    net.from_nx(G)

    # FIXED OPTIONS: Edge font is now white with a dark background stroke so it stands out perfectly.
    net.set_options("""
    var options = {
      "nodes": {
        "borderWidth": 2,
        "borderWidthSelected": 4,
        "font": { "size": 14, "face": "Tahoma", "color": "#ffffff" }
      },
      "edges": {
        "color": { "inherit": false, "color": "#aaaaaa" },
        "smooth": { "type": "continuous", "roundness": 0.4 },
        "font": { "size": 11, "color": "#ffffff", "strokeWidth": 4, "strokeColor": "#0b1519", "align": "horizontal" }
      },
      "physics": {
        "barnesHut": {
          "gravitationalConstant": -20000,
          "centralGravity": 0.3,
          "springLength": 250,
          "springConstant": 0.04,
          "damping": 0.09
        },
        "minVelocity": 0.75
      }
    }
    """)

    output_file = "evidence_evaluator_graph.html"
    net.save_graph(output_file)
    print(f"Success! Open '{output_file}' in your web browser.")


if __name__ == "__main__":
    build_interactive_graph("synthetic_banking_logs.json")
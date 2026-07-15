"""
=============================================================================
  QUANTUM-SAFE FORENSICS — NetworkX Graph Engine (Forensic Timeline)
=============================================================================
  Activated by the Risk Engine when a CRITICAL alert fires.

  Builds two forensic views:
    1. BACKWARD timeline (30 days)  — who gave the user access to this asset?
       Walks the graph in REVERSE: who granted privileges, who they connect to.
    2. FORWARD timeline (2-hop)     — who else is in this asset RIGHT NOW?
       Walks the graph FORWARD from the alerted user's recent activity.

  Graph model:
    Nodes : users and assets (labelled by type)
    Edges : directed, labelled by action + timestamp + log_id + bytes
=============================================================================
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Optional

try:
    import networkx as nx
except ImportError:
    raise SystemExit(
        "[graph_engine] NetworkX is required.\n"
        "  Install with:  pip install networkx"
    )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BACKWARD_DAYS = 30   # How far back to build the access-chain graph
FORWARD_HOPS  = 2    # How many hops forward from the alerted user


# ---------------------------------------------------------------------------
# Graph Engine
# ---------------------------------------------------------------------------

class GraphEngine:
    """
    Builds a directed multigraph from log events and performs forensic
    traversal after a UEBA alert fires.
    """

    def __init__(self):
        # MultiDiGraph allows multiple edges between the same pair of nodes
        # (e.g. a user can authenticate and export from the same asset)
        self._graph: nx.MultiDiGraph = nx.MultiDiGraph()

    # ------------------------------------------------------------------
    # Ingest
    # ------------------------------------------------------------------

    def ingest_logs(self, logs: list) -> None:
        """
        Build the full graph from all logs.
        Each log entry becomes a directed edge: source_user -> target_asset
        """
        for log in logs:
            payload    = log["payload"]
            log_id     = log["log_id"]
            user       = payload["source_user"]
            asset      = payload["target_asset"]
            action     = payload["action"]
            bytes_tx   = payload.get("bytes_transferred", 0)
            ts_str     = payload["timestamp"]
            ts         = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))

            # Add user node
            if not self._graph.has_node(user):
                self._graph.add_node(user, node_type="USER")

            # Add asset node
            if not self._graph.has_node(asset):
                self._graph.add_node(asset, node_type="ASSET")

            # Add directed edge: user -> asset
            self._graph.add_edge(
                user, asset,
                log_id    = log_id,
                action    = action,
                timestamp = ts,
                bytes_transferred = bytes_tx,
            )

            # Special: GRANTED_PRIVILEGE / REVOKED_PRIVILEGE create an
            # admin -> user relationship that the backward chain needs.
            # We model this as:  admin -> asset (standard) + admin -> user (implied)
            # For the purpose of backward traversal we also add:
            #   admin --[GRANTED_PRIVILEGE]--> asset
            # which already happens above. The traversal will find admins
            # who touched the same asset.

    # ------------------------------------------------------------------
    # Forensic Queries
    # ------------------------------------------------------------------

    def backward_chain(
        self,
        alerted_user:  str,
        alerted_asset: str,
        alert_ts:      datetime,
        days:          int = BACKWARD_DAYS,
    ) -> dict:
        """
        30-day backward forensic timeline.

        Finds every user and action that touched `alerted_asset` in the
        30 days before the alert, answering:
          "Who gave this user access / who else interacted with this asset?"
        """
        cutoff = alert_ts - timedelta(days=days)
        result = {
            "query":         "BACKWARD_CHAIN",
            "asset":         alerted_asset,
            "lookback_days": days,
            "alert_ts":      alert_ts.isoformat(),
            "cutoff_ts":     cutoff.isoformat(),
            "actors":        [],
        }

        for u, a, data in self._graph.edges(data=True):
            if a != alerted_asset:
                continue
            edge_ts = data.get("timestamp")
            if edge_ts is None or edge_ts < cutoff or edge_ts > alert_ts:
                continue
            result["actors"].append({
                "actor":   u,
                "action":  data["action"],
                "log_id":  data["log_id"],
                "ts":      edge_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "bytes":   data["bytes_transferred"],
            })

        # Sort chronologically
        result["actors"].sort(key=lambda x: x["ts"])
        return result

    def forward_reachability(
        self,
        alerted_user: str,
        alert_ts:     datetime,
        hops:         int = FORWARD_HOPS,
    ) -> dict:
        """
        2-hop forward reachability from the alerted user.

        Finds what assets the alerted user recently accessed and who else
        has accessed those assets within the same timeframe, answering:
          "Who else is in these systems right now?"
        """
        result = {
            "query":       "FORWARD_REACHABILITY",
            "origin_user": alerted_user,
            "hops":        hops,
            "alert_ts":    alert_ts.isoformat(),
            "reachable":   [],
        }

        if alerted_user not in self._graph:
            return result

        # BFS up to `hops` steps
        visited_nodes = set()
        frontier = {alerted_user}

        for hop in range(hops):
            next_frontier = set()
            for node in frontier:
                for neighbor in self._graph.successors(node):
                    if neighbor not in visited_nodes and neighbor != alerted_user:
                        next_frontier.add(neighbor)
                        # Gather any users who also touched this neighbor
                        if self._graph.nodes[neighbor].get("node_type") == "ASSET":
                            for other_user in self._graph.predecessors(neighbor):
                                if other_user != alerted_user:
                                    # Get most recent edge between other_user and neighbor
                                    edges = self._graph.get_edge_data(other_user, neighbor)
                                    if edges:
                                        for key, edge_data in edges.items():
                                            result["reachable"].append({
                                                "hop":    hop + 1,
                                                "user":   other_user,
                                                "asset":  neighbor,
                                                "action": edge_data["action"],
                                                "log_id": edge_data["log_id"],
                                                "ts":     edge_data["timestamp"].strftime(
                                                              "%Y-%m-%dT%H:%M:%SZ"
                                                          ),
                                            })
            visited_nodes |= frontier
            frontier = next_frontier

        # Deduplicate by (user, asset, action)
        seen = set()
        deduped = []
        for r in result["reachable"]:
            key = (r["user"], r["asset"], r["action"])
            if key not in seen:
                seen.add(key)
                deduped.append(r)

        result["reachable"] = sorted(deduped, key=lambda x: (x["hop"], x["ts"]))
        return result

    def graph_stats(self) -> dict:
        """Return basic graph statistics."""
        users  = [n for n, d in self._graph.nodes(data=True) if d.get("node_type") == "USER"]
        assets = [n for n, d in self._graph.nodes(data=True) if d.get("node_type") == "ASSET"]
        return {
            "total_nodes": self._graph.number_of_nodes(),
            "total_edges": self._graph.number_of_edges(),
            "users":       users,
            "assets":      assets,
        }

    # ------------------------------------------------------------------
    # Reporting helpers
    # ------------------------------------------------------------------

    def format_backward_report(self, chain: dict) -> str:
        lines = [
            "",
            "-" * 66,
            f"  [GRAPH] BACKWARD CHAIN — Asset: {chain['asset']}",
            f"  Lookback: {chain['lookback_days']} days before {chain['alert_ts']}",
            "-" * 66,
        ]
        if not chain["actors"]:
            lines.append("  No prior access found in this window.")
        else:
            for actor in chain["actors"]:
                lines.append(
                    f"  [{actor['ts']}]  {actor['actor']:20s}  "
                    f"{actor['action']:25s}  {actor['log_id']}  "
                    f"({actor['bytes']}B)"
                )
        lines.append("-" * 66)
        return "\n".join(lines)

    def format_forward_report(self, reachability: dict) -> str:
        lines = [
            "",
            "-" * 66,
            f"  [GRAPH] FORWARD REACHABILITY — Origin: {reachability['origin_user']}",
            f"  Hops: {reachability['hops']}  |  Alert time: {reachability['alert_ts']}",
            "-" * 66,
        ]
        if not reachability["reachable"]:
            lines.append("  No co-located users found within 2 hops.")
        else:
            for r in reachability["reachable"]:
                lines.append(
                    f"  [HOP {r['hop']}]  {r['user']:20s}  was also on  "
                    f"{r['asset']:20s}  via {r['action']}  ({r['ts']})"
                )
        lines.append("-" * 66)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Standalone test harness
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import os, json

    base = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(base, "synthetic_banking_logs.json"), encoding="utf-8") as f:
        logs = json.load(f)

    ge = GraphEngine()
    ge.ingest_logs(logs)

    stats = ge.graph_stats()
    print(f"\n[Graph Engine] Nodes: {stats['total_nodes']}  Edges: {stats['total_edges']}")
    print(f"  Users : {stats['users']}")
    print(f"  Assets: {stats['assets']}")

    # Demo: backward chain for User_Charlie on Customer_CRM
    ts = datetime.fromisoformat("2026-06-01T07:29:00+00:00")
    chain = ge.backward_chain("User_Charlie", "Customer_CRM", ts)
    print(ge.format_backward_report(chain))

    reach = ge.forward_reachability("User_Charlie", ts)
    print(ge.format_forward_report(reach))

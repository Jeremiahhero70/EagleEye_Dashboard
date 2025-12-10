"""
WazuhBoard Formatters - Simplified result formatting
"""

from typing import Dict, Any, List
import json

def format_query_results(raw_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format raw Elasticsearch query results into structured dashboard format
    """
    try:
        hits = raw_results.get("hits", {})
        total = hits.get("total", {}).get("value", 0) if isinstance(hits.get("total"), dict) else hits.get("total", 0)
        documents = hits.get("hits", [])

        # Extract basic information
        formatted = {
            "total_hits": total,
            "max_score": hits.get("max_score"),
            "documents": []
        }

        # Format each document
        for doc in documents:
            source = doc.get("_source", {})
            formatted_doc = {
                "id": doc.get("_id"),
                "index": doc.get("_index"),
                "score": doc.get("_score"),
                "timestamp": source.get("@timestamp"),
                "agent": {
                    "id": source.get("agent", {}).get("id"),
                    "name": source.get("agent", {}).get("name"),
                    "ip": source.get("agent", {}).get("ip")
                },
                "rule": {
                    "id": source.get("rule", {}).get("id"),
                    "level": source.get("rule", {}).get("level"),
                    "description": source.get("rule", {}).get("description"),
                    "groups": source.get("rule", {}).get("groups", [])
                },
                "data": source.get("data", {}),
                "full_log": source.get("full_log"),
                "decoder": source.get("decoder", {})
            }
            formatted["documents"].append(formatted_doc)

        return formatted

    except Exception as e:
        return {
            "error": f"Failed to format results: {str(e)}",
            "raw_results": raw_results
        }

def format_stats_for_display(stats: Dict[str, Any]) -> str:
    """
    Format statistics for display in the dashboard
    """
    lines = []

    # Total alerts
    total = stats.get("total_alerts", 0)
    lines.append(f"Total Alerts: {total}")

    # Severity breakdown
    severity = stats.get("severity_breakdown", {})
    if severity:
        lines.append("\nSeverity Breakdown:")
        for level, count in sorted(severity.items(), key=lambda x: int(x[0])):
            lines.append(f"  Level {level}: {count}")

    # Top rules
    top_rules = stats.get("top_rules", [])
    if top_rules:
        lines.append("\nTop Rules:")
        for rule in top_rules[:5]:  # Show top 5
            lines.append(f"  Rule {rule['rule_id']}: {rule['count']} alerts")

    # Top source IPs
    top_ips = stats.get("top_source_ips", [])
    if top_ips:
        lines.append("\nTop Source IPs:")
        for ip in top_ips[:5]:  # Show top 5
            lines.append(f"  {ip['ip']}: {ip['count']} alerts")

    # Active agents
    agents = stats.get("active_agents", 0)
    lines.append(f"\nActive Agents: {agents}")

    return "\n".join(lines)
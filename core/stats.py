"""
WazuhBoard Statistics Module - Fixed Client Scoping
Properly handles multi-tenant index patterns and client filtering
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from core.connectors.elasticsearch_connector import ElasticsearchConnector
from core.config import config

logger = logging.getLogger(__name__)


def get_dashboard_statistics(client_name: Optional[str] = None, time_range: str = "24h") -> Dict[str, Any]:
    """
    Fetch comprehensive dashboard statistics for a specific client
    Automatically scopes queries to client-specific indices
    """
    try:
        # Get client-specific Elasticsearch configuration
        es_config = config.get_elasticsearch_config(client_name)
        # Pass client_name to connector for auto-scoping indices
        es_connector = ElasticsearchConnector(es_config, client_name=client_name)
        
        stats = {}
        
        # Determine the correct index pattern based on client
        if client_name:
            # Try client-prefixed pattern first: "lab:wazuh-alerts-*"
            alert_index = f"{client_name}:wazuh-alerts-*"
            monitoring_index = f"{client_name}:wazuh-monitoring-*"
        else:
            # Global pattern
            alert_index = "wazuh-alerts-*"
            monitoring_index = "wazuh-monitoring-*"
        
        logger.info(f"Fetching stats for client={client_name} using indices: {alert_index}")
        
        # Determine timeframe
        time_map = {"24h": "now-24h", "7d": "now-7d", "30d": "now-30d"}
        es_time_range = time_map.get(time_range, "now-24h")
        interval_map = {"24h": "1h", "7d": "6h", "30d": "1d"}
        histogram_interval = interval_map.get(time_range, "1h")
        
        # Fetch all statistics (connector handles client-scoping automatically)
        stats.update(_get_alerts_per_hour(es_connector, alert_index, es_time_range, histogram_interval))
        
        sev_result = _get_severity_breakdown(es_connector, alert_index, es_time_range)
        stats.update({"severity_breakdown": sev_result.get("severity_breakdown", [])})
        stats.update({"severity_summary": sev_result.get("severity_summary", {})})
        
        stats.update(_get_top_rules(es_connector, alert_index, es_time_range))
        stats.update(_get_top_agents(es_connector, alert_index))
        stats.update(_get_top_source_ips(es_connector, alert_index, es_time_range))
        stats.update(_get_alert_trends(es_connector, alert_index, es_time_range))
        stats.update(_get_agent_status(es_connector, monitoring_index))
        
        # Add convenience totals
        summary = stats.get("severity_summary", {})
        stats["critical_alerts"] = summary.get("critical", 0)
        stats["total_alerts"] = sum(summary.values()) if summary else 0
        
        return stats
        
    except Exception as e:
        logger.error(f"Error fetching dashboard statistics for client {client_name}: {e}", exc_info=True)
        return {
            "error": str(e),
            "alerts_per_hour": [],
            "severity_breakdown": [],
            "severity_summary": {},
            "top_rules": [],
            "top_agents": [],
            "top_source_ips": [],
            "alert_trends": [],
            "agent_health": {"total": 0, "online": 0, "offline": 0}
        }


def _get_alerts_per_hour(es_connector, index: str, es_time_range: str, interval: str) -> Dict[str, Any]:
    """Get alerts count over time"""
    query = {
        "query": {
            "range": {
                "@timestamp": {"gte": es_time_range, "lte": "now"}
            }
        },
        "size": 0,
        "aggs": {
            "alerts_per_hour": {
                "date_histogram": {
                    "field": "@timestamp",
                    "calendar_interval": interval,
                    "format": "yyyy-MM-dd HH:mm:ss"
                }
            }
        }
    }
    
    try:
        result = es_connector.search(index, query)
        buckets = result.get("aggregations", {}).get("alerts_per_hour", {}).get("buckets", [])
        
        alerts_per_hour = [
            {
                "timestamp": bucket["key_as_string"],
                "count": bucket["doc_count"]
            }
            for bucket in buckets
        ]
        
        return {"alerts_per_hour": alerts_per_hour}
    except Exception as e:
        logger.error(f"Error fetching alerts per hour: {e}")
        return {"alerts_per_hour": []}


def _get_severity_breakdown(es_connector, index: str, es_time_range: str) -> Dict[str, Any]:
    """Get breakdown of alerts by severity level"""
    query = {
        "size": 0,
        "query": {
            "range": {
                "@timestamp": {"gte": es_time_range, "lte": "now"}
            }
        },
        "aggs": {
            "severity_breakdown": {
                "terms": {
                    "field": "rule.level",
                    "size": 20
                }
            }
        }
    }
    
    try:
        result = es_connector.search(index, query)
        buckets = result.get("aggregations", {}).get("severity_breakdown", {}).get("buckets", [])
        
        severity_data = [
            {
                "level": int(bucket["key"]),
                "count": bucket["doc_count"]
            }
            for bucket in buckets
        ]
        
        # Categorize by severity bands
        severity_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for b in severity_data:
            level = b["level"]
            cnt = b.get("count", 0)
            if level >= 15:
                severity_summary["critical"] += cnt
            elif level >= 12:
                severity_summary["high"] += cnt
            elif level >= 7:
                severity_summary["medium"] += cnt
            else:
                severity_summary["low"] += cnt
        
        return {"severity_breakdown": severity_data, "severity_summary": severity_summary}
    except Exception as e:
        logger.error(f"Error fetching severity breakdown: {e}")
        return {"severity_breakdown": [], "severity_summary": {}}


def _get_top_rules(es_connector, index: str, es_time_range: str) -> Dict[str, Any]:
    """Get top 10 most triggered rules by description"""
    query = {
        "size": 0,
        "query": {
            "range": {
                "@timestamp": {"gte": es_time_range, "lte": "now"}
            }
        },
        "aggs": {
            "top_rules": {
                "terms": {
                    "field": "rule.description",
                    "size": 10
                }
            }
        }
    }
    
    try:
        result = es_connector.search(index, query)
        buckets = result.get("aggregations", {}).get("top_rules", {}).get("buckets", [])
        
        top_rules = [
            {
                "description": bucket["key"],
                "count": bucket["doc_count"]
            }
            for bucket in buckets
        ]
        
        return {"top_rules": top_rules}
    except Exception as e:
        logger.error(f"Error fetching top rules: {e}")
        return {"top_rules": []}


def _get_top_agents(es_connector, index: str) -> Dict[str, Any]:
    """Get top 10 agents by alert count"""
    query = {
        "query": {"match_all": {}},
        "size": 0,
        "aggs": {
            "top_agents": {
                "terms": {
                    "field": "agent.name",
                    "size": 10
                }
            }
        }
    }
    
    try:
        result = es_connector.search(index, query)
        buckets = result.get("aggregations", {}).get("top_agents", {}).get("buckets", [])
        
        top_agents = [
            {
                "agent_name": bucket["key"],
                "count": bucket["doc_count"]
            }
            for bucket in buckets
        ]
        
        return {"top_agents": top_agents}
    except Exception as e:
        logger.error(f"Error fetching top agents: {e}")
        return {"top_agents": []}


def _get_top_source_ips(es_connector, index: str, es_time_range: str = "now-24h") -> Dict[str, Any]:
    """Get top 10 Office365 source IPs with country information"""
    query = {
        "query": {
            "range": {
                "@timestamp": {"gte": es_time_range, "lte": "now"}
            }
        },
        "size": 0,
        "aggs": {
            "top_source_ips": {
                "terms": {
                    "field": "data.office365.ClientIP",
                    "size": 10
                },
                "aggs": {
                    "country": {
                        "terms": {
                            "field": "GeoLocation.country_name",
                            "size": 1
                        }
                    }
                }
            }
        }
    }
    
    try:
        result = es_connector.search(index, query)
        buckets = result.get("aggregations", {}).get("top_source_ips", {}).get("buckets", [])
        
        top_ips = [
            {
                "ip": bucket["key"],
                "count": bucket["doc_count"],
                "country": bucket.get("country", {}).get("buckets", [{}])[0].get("key", "Unknown")
            }
            for bucket in buckets
            if bucket["key"] not in ["", "0.0.0.0"]
        ]
        
        return {"top_source_ips": top_ips}
    except Exception as e:
        logger.error(f"Error fetching top source IPs: {e}")
        return {"top_source_ips": []}


def _get_alert_trends(es_connector, index: str, es_time_range: str) -> Dict[str, Any]:
    """Get alert trends over 7 days"""
    query = {
        "size": 0,
        "query": {
            "range": {
                "@timestamp": {"gte": es_time_range, "lte": "now"}
            }
        },
        "aggs": {
            "daily_trends": {
                "date_histogram": {
                    "field": "@timestamp",
                    "calendar_interval": "day",
                    "format": "yyyy-MM-dd"
                }
            }
        }
    }
    
    try:
        result = es_connector.search(index, query)
        buckets = result.get("aggregations", {}).get("daily_trends", {}).get("buckets", [])
        
        trends = [
            {
                "date": bucket["key_as_string"],
                "count": bucket["doc_count"]
            }
            for bucket in buckets
        ]
        
        return {"alert_trends": trends}
    except Exception as e:
        logger.error(f"Error fetching alert trends: {e}")
        return {"alert_trends": []}


def _get_agent_status(es_connector, index: str) -> Dict[str, Any]:
    """Get agent status from monitoring indices"""
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": "now-2h"}}}
                ],
                "must_not": [
                    {"term": {"id": "000"}}
                ]
            }
        },
        "aggs": {
            "agents": {
                "terms": {"field": "id", "size": 1000},
                "aggs": {
                    "latest": {
                        "top_hits": {
                            "size": 1,
                            "sort": [{"timestamp": "desc"}],
                            "_source": ["status", "name"]
                        }
                    }
                }
            }
        }
    }
    
    try:
        result = es_connector.search(index, query)
        buckets = result.get("aggregations", {}).get("agents", {}).get("buckets", [])
        
        online = 0
        offline = 0
        
        for bucket in buckets:
            latest_hits = bucket.get("latest", {}).get("hits", {}).get("hits", [])
            if latest_hits:
                status = latest_hits[0].get("_source", {}).get("status", "").lower()
                if status in ("active", "connected"):
                    online += 1
                else:
                    offline += 1
        
        return {
            "agent_health": {
                "total": online + offline,
                "online": online,
                "offline": offline
            }
        }
    except Exception as e:
        logger.error(f"Error fetching agent status: {e}")
        return {"agent_health": {"total": 0, "online": 0, "offline": 0}}
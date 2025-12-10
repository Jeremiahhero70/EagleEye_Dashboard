"""
WazuhBoard API - Fixed endpoints for dashboard
"""

from fastapi import APIRouter, HTTPException, Request
from typing import Dict, Any, Optional
import logging

from core.stats import get_dashboard_statistics
from core.connectors.elasticsearch_connector import ElasticsearchConnector
from core.formatter import format_query_results
from core.config import config

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/clients")
async def get_clients():
    """
    Get list of available clients for multi-tenant dashboard
    """
    try:
        clients = config.get_client_names()
        default_client = config.get_default_client()

        client_list = []
        for client_name in clients:
            display_name = config.get_client_display_name(client_name)
            client_list.append({
                "name": client_name,
                "description": display_name,
            })

        return {
            "clients": client_list,
            "default_client": default_client
        }
    except Exception as e:
        logger.error(f"Error loading clients: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to load clients: {str(e)}")


@router.get("/debug/sample")
async def get_sample_document(index: str = "wazuh-alerts-*", client: str = None):
    """
    Get a sample document from the specified index for debugging
    """
    try:
        es_config = config.get_elasticsearch_config(client)
        es_connector = ElasticsearchConnector(es_config)

        query = {
            "size": 1,
            "sort": [{"@timestamp": {"order": "desc"}}]
        }

        result = es_connector.search(index, query)
        hits = result.get("hits", {}).get("hits", [])
        if hits:
            return {"sample": hits[0]["_source"]}
        else:
            return {"sample": None, "message": "No documents found"}

    except Exception as e:
        logger.error(f"Error fetching sample: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch sample: {str(e)}")


@router.post("/stats/dashboard")
async def get_dashboard_stats(request: Request) -> Dict[str, Any]:
    """
    Get comprehensive dashboard statistics
    Accepts JSON body with optional 'client' and 'time_range' parameters
    
    Request body:
    {
        "client": "lab",
        "time_range": "24h"
    }
    """
    try:
        # Parse request body
        body = {}
        try:
            body = await request.json()
        except:
            pass  # Empty body is OK
        
        client_name = body.get("client") if body else None
        time_range = body.get("time_range", "24h") if body else "24h"

        logger.info(f"Fetching dashboard stats for client={client_name}, time_range={time_range}")
        
        stats = get_dashboard_statistics(client_name, time_range)
        return stats

    except Exception as e:
        logger.error(f"Error fetching dashboard stats: {e}", exc_info=True)
        return {
            "error": str(e),
            "alerts_per_hour": [],
            "severity_breakdown": [],
            "severity_summary": {},
            "top_rules": [],
            "top_agents": [],
            "top_source_ips": [],
            "alert_trends": [],
            "agent_health": {"total": 0, "online": 0, "offline": 0},
            "total_alerts": 0,
            "critical_alerts": 0
        }


@router.post("/query")
async def execute_query(request: Request, client: Optional[str] = None) -> Dict[str, Any]:
    """
    Execute raw Elasticsearch query and return structured JSON result

    Expected query format:
    {
        "index": "wazuh-alerts-*",
        "body": {
            "query": {...},
            "size": 100,
            "sort": [...]
        }
    }
    """
    try:
        body = await request.json()
        
        # Get client-specific Elasticsearch configuration
        es_config = config.get_elasticsearch_config(client)
        es_connector = ElasticsearchConnector(es_config)

        # Extract query parameters
        index = body.get("index", "wazuh-alerts-*")
        query_body = body.get("body", {})

        logger.info(f"Executing query on index={index}")

        # Execute the query
        raw_results = es_connector.search(index=index, body=query_body)

        # Format the results
        formatted_results = format_query_results(raw_results)

        return {
            "success": True,
            "data": formatted_results,
            "total_hits": raw_results.get("hits", {}).get("total", {}).get("value", 0)
        }

    except Exception as e:
        logger.error(f"Error executing query: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Query execution failed: {str(e)}")
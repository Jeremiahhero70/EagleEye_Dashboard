"""
WazuhBoard Elasticsearch Connector - Auto Client Scoping
Handles per-client index patterns and credentials automatically
"""

import requests
import time
import logging
from typing import Dict, Any, List, Optional
from core.config import config

logger = logging.getLogger(__name__)


class ElasticsearchConnector:
    """Elasticsearch connector with automatic client-scoped index handling"""

    def __init__(self, es_config: Optional[Dict[str, Any]] = None, client_name: Optional[str] = None):
        """
        Initialize connector with config
        
        Args:
            es_config: Elasticsearch configuration dict
            client_name: Optional client name for auto-scoping indices
        """
        self.client_name = client_name
        
        if es_config:
            self.host = es_config.get("host", "localhost")
            self.port = es_config.get("port", 9200)
            self.scheme = es_config.get("scheme", "http")
            self.username = es_config.get("username")
            self.password = es_config.get("password")
            self.verify_ssl = es_config.get("verify_ssl", True)
        else:
            # Fallback to environment/defaults
            self.host = config.env.get("dashboard_host", "localhost").replace("https://", "").replace("http://", "")
            self.port = config.env.get("dashboard_port", 9200)
            self.scheme = "https" if config.env.get("dashboard_host", "").startswith("https") else "http"
            self.username = config.env.get("dashboard_user")
            self.password = config.env.get("dashboard_pass")
            self.verify_ssl = config.env.get("verify_ssl", True)

        self.indexer_url = f"{self.scheme}://{self.host}:{self.port}"
        self.timeout = (5.0, 20.0)  # connect, read timeouts
        self.max_retries = 2
        self.retry_backoff = 1.5

        logger.info(f"ElasticsearchConnector initialized: {self.indexer_url} (client={client_name})")

    def _scope_index(self, index: str) -> str:
        """
        Auto-scope index pattern to client if applicable
        
        Example: "wazuh-alerts-*" becomes "lab:wazuh-alerts-*" if client_name is "lab"
        """
        if not self.client_name:
            return index
        
        # If index already has client prefix, return as-is
        if ":" in index:
            return index
        
        # Add client prefix
        return f"{self.client_name}:{index}"

    def _execute_search_request(self, search_url: str, query: Dict[str, Any], description: str) -> Dict[str, Any]:
        """Execute Elasticsearch search request with retry logic"""
        auth = (self.username, self.password) if self.username and self.password else None

        for attempt in range(self.max_retries + 1):
            try:
                response = requests.post(
                    search_url,
                    json=query,
                    auth=auth,
                    verify=self.verify_ssl,
                    timeout=self.timeout
                )

                if response.status_code == 200:
                    return response.json()
                else:
                    logger.error(f"ES request failed ({response.status_code}): {response.text[:200]}")
                    return {}

            except requests.exceptions.RequestException as e:
                logger.warning(f"ES request attempt {attempt + 1} failed: {e}")
                if attempt < self.max_retries:
                    time.sleep(self.retry_backoff * (attempt + 1))
                else:
                    logger.error(f"All ES request attempts failed for {description}")
                    return {}

        return {}

    def search(self, index: str, body: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """
        Execute search query against Elasticsearch
        Automatically scopes index to client if configured
        """
        scoped_index = self._scope_index(index)
        search_url = f"{self.indexer_url}/{scoped_index}/_search"
        logger.debug(f"Searching {scoped_index}: {body}")
        return self._execute_search_request(search_url, body, f"search {scoped_index}")

    def get_indices(self) -> List[str]:
        """
        Get list of available indices
        Returns both client-scoped and global indices
        """
        try:
            response = requests.get(
                f"{self.indexer_url}/_cat/indices",
                params={"format": "json"},
                auth=(self.username, self.password) if self.username and self.password else None,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                indices = response.json()
                filtered = []
                
                for idx in indices:
                    name = idx.get("index", "")
                    # Match both global and client-scoped wazuh indices
                    if "wazuh" in name:
                        # If we have a client_name, prioritize client-scoped indices
                        if self.client_name:
                            if self.client_name in name or ":" not in name:
                                filtered.append(name)
                        else:
                            # Global scope: include indices without client prefix or with any prefix
                            filtered.append(name)
                
                logger.debug(f"Found indices for {self.client_name or 'global'}: {filtered}")
                return filtered
            
            return []
        except Exception as e:
            logger.error(f"Error getting indices: {e}")
            return []

    def ping(self) -> bool:
        """
        Test connection to Elasticsearch
        """
        try:
            response = requests.get(
                f"{self.indexer_url}/_cluster/health",
                auth=(self.username, self.password) if self.username and self.password else None,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Elasticsearch ping failed: {e}")
            return False